// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <algorithm>
#include <signal.h>
#include <climits>
#include <fstream>
#include "OpenDict.h"
#include "Reporter.h"
#include "util.h"

#ifdef DEBUG
#define ASSERT_VALID(o) 0->AssertValid()
#else
#define ASSERT_VALID(o)
#endif//DEBUG

struct IterCookie {
	IterCookie(Dictionary* d) : robust(false),d(d),next(-1), inserted(0), visited(0){}
	bool robust;
	Dictionary* d;
	int next; //index for next valid entry. -1 is default not started yet.

	//the following only used in robust cookies.
	std::vector<DictEntry>* inserted;	// inserted while iterating
	std::vector<DictEntry>* visited; //visited but moved across next due to insertion.
	void MakeRobust()
		{
		robust = true;
		ASSERT( next <0 ); //must make it robust before any iteration.
		inserted = new std::vector<DictEntry>();
		visited = new std::vector<DictEntry>();
		ASSERT(d&&d->cookies);
		d->cookies->push_back(this); 
		}

	void AssertValid() const
		{
		ASSERT(d && -1 <= next && next <= d->Capacity());
		ASSERT((!robust && !inserted && !visited) || (robust && inserted && visited));
		}

	~IterCookie()
		{
			ASSERT_VALID(this);
			if( robust)
				{
				d->cookies->erase(std::remove(d->cookies->begin(), d->cookies->end(), this));
				delete inserted;
				delete visited;
				}
		}
};

/////////////////////////////////////////////////////////////////////////////////////////////////
//bucket math
int Dictionary::Log2(int num) const
	{
	int i=0;
	while(num>>=1)
		i++;
	return i;
	}

int Dictionary::Buckets(bool expected) const 
	{ 
	int buckets = (1 << log2_buckets); 
	if( expected)
		return buckets;
	return table ? buckets : 0;
	}

int Dictionary::Capacity(bool expected) const 
	{ 
	int capacity = (1 << log2_buckets) + (log2_buckets+0); 
	if( expected)
		return capacity;
	return table ? capacity : 0;
	}

int Dictionary::ThresholdEntries() const
	{ 	
	//SizeUp the dictionary when dict is 75% full
	//However, when the dict is small (<=2^4+4=20), SizeUp only when dict is 100% full (right after the current insertion)
	//the dict will always SizeUp when the last entry is occupied after current insertion.
	//the idea is the current insertion is always successful.
	int capacity = Capacity();
	if( log2_buckets <= DICT_THRESHOLD_BITS)
		return capacity; //20 or less elements, 1.0, only size up when necessary.
	return capacity - (capacity>>DICT_LOAD_FACTOR_BITS); 
	}

hash_t Dictionary::FibHash(hash_t h) const
	{
	//refer for details: https://probablydance.com/2018/06/16/fibonacci-hashing-the-optimization-that-the-world-forgot-or-a-better-alternative-to-integer-modulo/
	//GoldenRatio phi = (sqrt(5)+1)/2 = 1.6180339887...
	//1/phi = phi - 1

	h &= HASH_MASK;
	h *= 11400714819323198485llu; //2^64/phi
	return h;
	}

//return position in dict with 2^bit size.
int Dictionary::BucketByHash(hash_t h, int log2_table_size) const //map h to n-bit
	{
	ASSERT(log2_table_size>=0);
	if( !log2_table_size )
		return 0; //<< >> breaks on  64.
	int m = 64 - log2_table_size;
	#ifdef DICT_NO_FIB_HASH
	hash_t hash = h;
	#else
	hash_t hash = FibHash(h);
	#endif//_FIB_HASH
	hash <<= m;
	hash >>= m;
	ASSERT(hash>=0);
	return hash;
	}

//given entry at index i, return it's perfect bucket position.
int Dictionary::BucketByPosition(int position) const
	{
	ASSERT( table && position>=0 && position < Capacity() && !table[position].Empty() );
	return position - table[position].distance;
	}

////////////////////////////////////////////////////////////////////////////////////////////////
//Cluster Math
////////////////////////////////////////////////////////////////////////////////////////////////
int Dictionary::HeadOfClusterByBucket(int bucket) const
{
    ASSERT(bucket>=0 && bucket < Buckets());
    int i = bucket;
	for(; i < Capacity() && !table[i].Empty() && BucketByPosition(i) < bucket; i++)
        if( BucketByPosition(i) == bucket)
			return i; //found.
	//not found.
	return -1; 
}

int Dictionary::TailOfClusterByBucket(int bucket) const
{
	int end = EndOfClusterByBucket(bucket);
	if( end - 1 >= 0 && !table[end-1].Empty() && BucketByPosition(end - 1) == bucket )
		return end - 1;
	return -1;
}

int Dictionary::EndOfClusterByBucket(int bucket) const
{
    ASSERT(bucket>=0 && bucket < Buckets());
    int i = bucket;
    while( i < Capacity() && !table[i].Empty() && BucketByPosition(i) <= bucket)
        i++;
    return i;
}

int Dictionary::HeadOfClusterByPosition( int position) const
	{//the first entry in bucket chain.
	ASSERT( 0 <= position && position < Capacity() && !table[position].Empty());
	//look backward for the first item with the same bucket as myself.
	int bucket = BucketByPosition(position);
	int i = position;
	while( i >= bucket && BucketByPosition(i) == bucket )
		i--; 
	return i == bucket ? i : i + 1;
	}

int Dictionary::TailOfClusterByPosition(int position) const
	{
	ASSERT( 0 <= position && position < Capacity() && !table[position].Empty());
	int bucket = BucketByPosition(position);
	int i = position;
	while( i < Capacity() && !table[i].Empty() && BucketByPosition(i) == bucket )
		i++; //stop just over the tail.
	return i - 1; 
	}

int Dictionary::EndOfClusterByPosition(int position) const
{
	return TailOfClusterByPosition(position)+1;
}

int Dictionary::OffsetInClusterByPosition(int position) const
	{
	ASSERT( 0 <= position && position < Capacity() && !table[position].Empty() );
	int head = HeadOfClusterByPosition(position);
	return position - head;
	}

//find next valid entry after index i (i not included). i can be empty.
int Dictionary::Next(int position) const
	{//can handle i=-1.
	ASSERT(table && -1 <= position && position < Capacity());
	do
		{
		position++;
		} while (position < Capacity() && table[position].Empty());
	return position;
	}

///////////////////////////////////////////////////////////////////////////////////////////////////////
//Debugging
///////////////////////////////////////////////////////////////////////////////////////////////////////////
#define DUMPIF(f) if(f) Dump(1)
#ifdef DEBUG
void Dictionary::AssertValid() const
	{
	bool valid = true;
	int n = num_entries;
	for(int i=Capacity()-1; i>=0; i--)
		if( table && !table[i].Empty())
			n--;
	ASSERT( (valid = (n==0)) );
	DUMPIF(!valid);

	//entries must clustered together 
	for(int i=1; i<Capacity(); i++)
		{
			if(table[i].Empty() )
				continue;

			if(table[i-1].Empty())
				{
				ASSERT( (valid=(table[i].distance == 0)));
				DUMPIF(!valid);
				}
			else 
				{
				ASSERT((valid=(table[i].bucket >= table[i-1].bucket)));
				DUMPIF(!valid);
				if(table[i].bucket == table[i-1].bucket )
					{
					ASSERT((valid=(table[i].distance == table[i-1].distance+1)));
					DUMPIF(!valid);
					}
				else
					{
					ASSERT((valid=(table[i].distance <= table[i-1].distance)));
					DUMPIF(!valid);
					}
				}
		}
	}
#endif//DEBUG

unsigned int Dictionary::MemoryAllocation() const
	{
	int size = padded_sizeof(*this);
	if( table)
		{
 		size += pad_size(Capacity() * sizeof(DictEntry));
		for ( int i = Capacity()-1; i>=0; i-- )
			if ( !table[i].Empty() && table[i].key_size > 8)
					size += pad_size(table[i].key_size);
		}
	if(order)
		size += padded_sizeof(std::vector<DictEntry>) + pad_size(sizeof(DictEntry) * order->capacity());
	return size;
	}

void Dictionary::DumpKeys() const
	{
	if(!table)
		return;
	char key_file[100];
	//detect string or binary from first key.
	int i=0; 
	while(table[i].Empty() && i<Capacity())
		i++;

	bool binary = false;
	const char* key = table[i].GetKey();
	for(int j=0; j<table[i].key_size; j++)
		if( !isprint(key[j]))
		{
			binary = true;
			break;
		}
	int max_distance = 0;

	DistanceStats(max_distance);
	if	( binary)
		{
		sprintf(key_file, "%d.%d.%d-%c.key", Length(), max_distance, MemoryAllocation()/Length(), rand()%26 + 'A');
		ofstream f(key_file, ios::binary|ios::out|ios::trunc);
		for(int i=0; i<Capacity(); i++)
			if( !table[i].Empty())
			{
				int key_size = table[i].key_size;
				f.write((const char*)&key_size, sizeof(int));
				f.write(table[i].GetKey(), table[i].key_size);
			}
		}
	else
		{
		sprintf(key_file, "%d.%d.%d-%d.ckey",Length(), max_distance, MemoryAllocation()/Length(), rand()%26 + 'A');
		ofstream f(key_file, ios::out|ios::trunc);
		for(int i=0; i<Capacity(); i++)
			if( !table[i].Empty())
			{
				string s((char*)table[i].GetKey(), table[i].key_size);
				f << s << endl;
			}
		}
	}

void Dictionary::DistanceStats(int& max_distance, int* distances, int num_distances) const
    {
	max_distance = 0;
	for(int i=0; i<num_distances; i++)
		distances[i] = 0;
	for(int i=0; i<Capacity(); i++)
		{
		if( table[i].Empty())
			continue;
		if( table[i].distance > max_distance)
			max_distance = table[i].distance;
		if( num_distances <= 0 || !distances)
			continue;
		if(table[i].distance >= num_distances-1)
			distances[num_distances-1]++;
		else
			distances[table[i].distance]++;
		}
	}

void Dictionary::Dump(int level) const
	{
	int key_size = 0;
	uint64_t val_size = 0;
	uint64_t connval_size = 0;
	for(int i=0; i<Capacity(); i++)
		{
		if( table[i].Empty())
			continue;
		key_size += pad_size(table[i].key_size);
		if( !table[i].value)
			continue;
		}

	#define DICT_NUM_DISTANCES 5
	int distances[DICT_NUM_DISTANCES];
	int max_distance = 0;
	DistanceStats(max_distance, distances, DICT_NUM_DISTANCES);
	printf("cap %'7d ent %'7d %'-7d load %.2f max_dist %2d mem %'10d mem/ent %3d key/ent %3d lg %2d remaps %1d remap_end %4d ",
		Capacity(), Length(), MaxLength(), (float)Length()/(table? Capacity() : 1), 
		max_distance, MemoryAllocation(), (MemoryAllocation())/(Length()?Length():1), key_size / (Length()?Length():1),
		log2_buckets, remaps, remap_end);
	if( Length() > 0)
		{
		for(int i=0; i<DICT_NUM_DISTANCES-1; i++)
			printf("[%d]%2d%% ", i, 100*distances[i]/Length());
		printf("[%d+]%2d%% ", DICT_NUM_DISTANCES-1, 100*distances[DICT_NUM_DISTANCES-1]/Length());
		}
	else
		printf("\n");
		
	printf("\n");
	if( level >= 1)
		{
		printf("%-10s %1s %-10s %-4s %-4s %-10s %-18s %-2s\n", "Index", "*","Bucket", "Dist", "Off", "Hash", "FibHash", "KeySize");
		for(int i=0; i<Capacity(); i++)
			if( table[i].Empty())
				printf("%'10d \n", i);
			else
				printf("%'10d %1s %'10d %4d %4d 0x%08x 0x%016lx(%3d) %2d\n", 
					i, (i<=remap_end? "*":  ""), BucketByPosition(i), (int)table[i].distance, OffsetInClusterByPosition(i), 
					uint(table[i].hash), FibHash(table[i].hash), (int)FibHash(table[i].hash)&0xFF, (int)table[i].key_size);
		}
	}

//////////////////////////////////////////////////////////////////////////////////////////////////
//Initialization.
////////////////////////////////////////////////////////////////////////////////////////////////////
Dictionary::Dictionary(dict_order ordering, int initial_size)
	: remaps(0), log2_buckets(0), num_iterators(0), remap_end(-1), num_entries(0), max_entries(0), 
	  cum_entries(0), delete_func(0), table(0), cookies(0), order(0)
	{	//initial_size = 1 << 10;
#ifdef DEBUG
	int sz = sizeof(*this);
	int psz = padded_sizeof(*this);
	int dsz = sizeof(DictEntry);
#endif//DEBUG
	if(initial_size > 0)
		{//if initial is specified, init the table right away, otherwise wait until the first insert to init. 
		log2_buckets = Log2(initial_size);
		Init();
		}
	if ( ordering == ORDERED )
		order = new std::vector<DictEntry>;
	}

Dictionary::~Dictionary()
	{
	Clear();//the place to free key memory. other place is to remove the entry
	}

void Dictionary::Clear()
	{
	if(table)
		{
		for ( int i = Capacity() - 1; i >= 0; i-- )
			{
			if( table[i].Empty())
				continue;
			if( delete_func )
				delete_func(table[i].value);
			table[i].Clear();
			}
		delete [] table;
		table = NULL;
		}

	if( order )
		{
		delete order;
		order = NULL;
		}
	if( cookies )
		{
		delete cookies;
		cookies = NULL;
		}
	log2_buckets = 0;
	num_iterators = 0;
	remaps = 0;
	remap_end = -1;
	num_entries = 0;
	max_entries = 0;
	}

void Dictionary::Init()
	{
	ASSERT(!table);
	table = (DictEntry*)malloc(sizeof(DictEntry)*Capacity(true));
	for(int i=Capacity()-1; i >= 0; i--)
		table[i].SetEmpty();
	}

// private
void generic_delete_func(void* v)
	{
	free(v);
	}

//////////////////////////////////////////////////////////////////////////////////////////
//Lookup

// Look up now also possibly modifies the entry. Why? if the entry is found but not positioned according to the current dict (so it's before SizeUp), it will be moved to the right position  so next looik up is fast.
void* Dictionary::Lookup(const HashKey* key) const
	{
	return Lookup(key->Key(), key->Size(), key->Hash());
	}

void* Dictionary::Lookup(const void* key, int key_size, hash_t h) const
	{
	Dictionary* d = const_cast<Dictionary*>(this);
	int position = d->LookupIndex(key, key_size, h);
	return position >= 0 ? table[position].value : NULL;
	}

//for verification purposes
int Dictionary::LinearLookupIndex(const void* key, int key_size, hash_t hash) const
	{
	for(int i=0; i<Capacity(); i++)
		if( !table[i].Empty() && table[i].Equal((const char*)key, key_size, hash))
			return i;
	return -1;
	}

///Lookup position for all possible table_sizes caused by remapping.
///Remap it immediately if not in iteration.
int Dictionary::LookupIndex(const void* key, int key_size, hash_t hash, int* insert_position, int* insert_distance)
	{
	ASSERT_VALID(this);
	int bucket = BucketByHash(hash, log2_buckets);
	int distance = 0;
	if( !table)
		return -1;
#ifdef DEBUG
	int linear_position = LinearLookupIndex(key, key_size, hash);
#endif//DEBUG
	int position = LookupIndex(key, key_size, hash, bucket, Capacity(), insert_position, insert_distance);
	if( position >= 0)
		{
		ASSERT(position == linear_position);//same as linearLookup
		return position;
		}

	for(int i=1; i<=remaps; i++)
		{
		int prev_bucket = BucketByHash(hash,log2_buckets - i);
		if( prev_bucket <= remap_end)
			{ //possibly here. insert_position & insert_distance returned on failed lookup is not valid in previous table_sizes.
			position = LookupIndex(key, key_size, hash, prev_bucket, remap_end+1); 
			if(position >= 0)
				{
				ASSERT(position == linear_position);//same as linearLookup
				//remap immediately if no iteration is on.
				if( !num_iterators)
					{
					Remap(position, &position);
					ASSERT(position == LookupIndex(key, key_size, hash));
					}
				return position;
				}
			}
		}
	//not found
#ifdef DEBUG
	if( linear_position >= 0)
		{//different. stop and try to see whats happending.
		ASSERT(false);
		//rerun the function in debugger to track down the bug.
		LookupIndex(key, key_size, hash);
		}
#endif//DEBUG			
	return -1;
	}

///
/// returns the position of the item if it exists. Otherwise return -1 but set the insert_position/insert_distance if required.
/// begin may not be the bucket for current table size. it's also used to search an item in prev table size.
int Dictionary::LookupIndex(const void* key, int key_size, hash_t hash, int bucket, int end, int* insert_position/*output*/, int* insert_distance/*output*/) 
	{
    ASSERT(bucket>=0 && bucket < Buckets());
	int i = bucket;
	for(; i < end && !table[i].Empty() && BucketByPosition(i) <= bucket; i++)
		if( BucketByPosition(i) == bucket && table[i].Equal((char*)key, key_size, hash))
			return i;
	//no such cluster, or not found in the cluster.			
    if(insert_position)
        *insert_position = i;
    if(insert_distance)
        *insert_distance = i - bucket;
    return -1;
	}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Insert
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

///This is external interface.
///If key exists, return its value, 
///If key doesn't exist, return NULL
void* Dictionary::Insert(void* key, int key_size, hash_t hash, void* val, int copy_key)
{ 	
	ASSERT_VALID(this);
	ASSERT(num_iterators == 0 || (cookies && cookies->size() == num_iterators)); //only robust iterators exist.
	if( !table )
		Init();//create table on first Insert to save memory on empty dicts.
	void* v = NULL;
	//if found. i is the position
	//if not found, i is the insert position, d is the distance of key on position i.
	int insert_position = -1, insert_distance = -1;
	int position = LookupIndex(key, key_size, hash, &insert_position, &insert_distance);
	if( position >= 0 )
		{
		v = table[position].value;
		table[position].value = val;
		if( !copy_key)
			delete (char*)key;
		
		if( order )
			{//set new v to order too.
			auto it = std::find(order->begin(), order->end(), table[position]);
			ASSERT(it != order->end());
			it->value = val;
			}
		if( cookies && !cookies->empty() )
			//need to set new v for cookies too.
			for( auto c: *cookies )
				{
				ASSERT_VALID(c);
				//ASSERT(false);
				auto it = std::find(c->inserted->begin(), c->inserted->end(), table[position]);
				if( it != c->inserted->end())
					it->value = val;
				}
		}
	else
		{
		//not found here.
		//allocate memory for key if necesary. key is updated to reflect internal key if necessary.
		DictEntry entry(key, key_size, hash, val, insert_distance, copy_key);  
		InsertRelocateAndAdjust(entry, insert_position); 
		if(order)
			order->push_back(entry);

		num_entries++;
		cum_entries++;
		if( max_entries < num_entries )
			max_entries = num_entries;
		if( num_entries > ThresholdEntries() )
			SizeUp();
		}

	//Remap after insert can adjust asap to shorten period of mixed table.
	//however, if remap happens right after size up, then it consumes more cpu for this cycle, a possible hickup point.
	if( Remapping())
		Remap(); 
	ASSERT_VALID(this);
	return v; 
	}

///e.distance is adjusted to be the one at insert_position. 
void Dictionary::InsertRelocateAndAdjust(DictEntry& entry, int insert_position)
	{
#ifdef DEBUG
	entry.bucket = BucketByHash(entry.hash,log2_buckets);
#endif//DEBUG
	int last_affected_position = insert_position;
	InsertAndRelocate(entry, insert_position, &last_affected_position);
	//if remapping in progress. adjust remap_end to step back a little to cover the new range if the changed range straddles over remap_end.
	if( Remapping() && insert_position <= remap_end && remap_end < last_affected_position )
		{//[i,j] range changed. if map_end in between. then possibly old entry pushed down across map_end. 
		remap_end = last_affected_position; //adjust to j on the conservative side.
		}

	if(cookies && !cookies->empty())
		for(auto c: *cookies)
			AdjustOnInsert(c, entry, insert_position, last_affected_position);			
}

/// insert entry into position, relocate other entries when necessary.
void Dictionary::InsertAndRelocate(DictEntry& entry, int insert_position, int* last_affected_position)
	{///take out the head of cluster and append to the end of the cluster.
    while(true)
    	{   
        if(insert_position >= Capacity())
        {
            ASSERT(insert_position == Capacity());
            SizeUp(); //copied all the items to new table. as it's just copying without remapping, insert_position is now empty.
            table[insert_position] = entry;
			if(last_affected_position)
            	*last_affected_position = insert_position;
            return;
        }
        if(table[insert_position].Empty())
        {   //the condition to end the loop.
            table[insert_position] = entry;
			if(last_affected_position)
            	*last_affected_position = insert_position;
			
            return;
        }
        //the to-be-swapped-out item appends to the end of its original cluster.
        auto t = table[insert_position];
        int next = EndOfClusterByPosition(insert_position);
        t.distance += next - insert_position;
        //swap
        table[insert_position] = entry;
        entry = t;
        insert_position = next; //append to the end of the current cluster.
    	}
	}

/// Adjust Cookies on Insert.
void Dictionary::AdjustOnInsert(IterCookie* c, const DictEntry& entry, int insert_position, int last_affected_position)
	{
	ASSERT(c);
	ASSERT_VALID(c);
	if(insert_position < c->next)
		c->inserted->push_back(entry);
	if( insert_position < c->next && c->next <= last_affected_position)
		{	
		int k = TailOfClusterByPosition(c->next);
		ASSERT(k >= 0 && k < Capacity());
		c->visited->push_back(table[k]);
		}
	}

void Dictionary::SizeUp()
	{
	int prev_capacity = Capacity();
	log2_buckets++;
	int capacity = Capacity();
	table = (DictEntry*)realloc(table, capacity*sizeof(DictEntry));
	for(int i=prev_capacity; i<capacity; i++)
		table[i].SetEmpty();
	
	//Remap from last to first in reverse order. 
	//SizeUp can be triggered by 2 conditions. one of it is the last space in the table is occupied and nowhere to put the new item.
	//In this case, table doubles and item put to [prev_capacity] with old hash. we need to cover this item.
	remap_end = prev_capacity; //prev_capacity instead of prev_capacity-1.
	//another remap starts.
	remaps++; //used in Lookup() to cover SizeUp with incomplete remaps.
	ASSERT(remaps <= log2_buckets);//because we only sizeUp, one direction. we know the previous log2_buckets.
	}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Remove
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void* Dictionary::Remove(const void* key, int key_size, hash_t hash, bool dont_delete)
	{//cookie adjustment: maintain inserts here. maintain next in lower level version.
	ASSERT_VALID(this);
	ASSERT(num_iterators == 0 || (cookies && cookies->size() == num_iterators)); //only robust iterators exist.
	ASSERT(!dont_delete); //this is a poorly designed flag. if on, the internal has nowhere to return and memory is lost.
	int position = LookupIndex(key, key_size, hash);
	if(position < 0)
		return NULL;
		
	DictEntry entry = RemoveRelocateAndAdjust(position);
	num_entries--;
	ASSERT(num_entries >= 0);
	//e is about to be invalid. remove it from all references.
	if(order)
		order->erase(std::remove(order->begin(), order->end(), entry));
	void* v = entry.value;
	entry.Clear();
	ASSERT_VALID(this);
	return v;
	}

DictEntry Dictionary::RemoveRelocateAndAdjust(int position)
	{
	int last_affected_position = position;
	DictEntry entry = RemoveAndRelocate(position, &last_affected_position);
#ifdef DEBUG
	//validation: index to i-1 should be continuous without empty spaces.
	for(int k=position; k<last_affected_position; k++)
		ASSERT(!table[k].Empty());
#endif//DEBUG	
	if(cookies && !cookies->empty())
		for(auto c: *cookies)
			AdjustOnRemove(c, entry, position, last_affected_position);

	return entry;
	}

DictEntry Dictionary::RemoveAndRelocate(int position, int* last_affected_position)
	{//fill the empty position with the tail of the cluster of position+1.
	ASSERT(position >= 0 && position < Capacity() && !table[position].Empty());
	DictEntry entry = table[position];
    while(true)
    	{
        if( position == Capacity() - 1 || table[position+1].Empty() || table[position+1].distance == 0)
        	{//no next cluster to fill, or next position is empty or next position is already in perfect bucket.
            table[position].SetEmpty();
			if(last_affected_position)
            	*last_affected_position = position;
            return entry;
        	}
        int next = TailOfClusterByPosition(position+1);
        table[position] = table[next];
        table[position].distance -= next - position; //distance improved for the item.
        position = next;
    	}
	return entry;
	}

void Dictionary::AdjustOnRemove(IterCookie* c, const DictEntry& entry, int position, int last_affected_position)
	{
	ASSERT_VALID(c);
	c->inserted->erase(std::remove(c->inserted->begin(), c->inserted->end(), entry), c->inserted->end());
	if( position < c->next && c->next <= last_affected_position)
		{
		int moved = HeadOfClusterByPosition(c->next-1);
		if( moved < position )
			moved = position; 
		c->inserted->push_back(table[moved]);
		}

	//if not already the end of the dictionary, adjust next to a valid one.	
	if( c->next < Capacity() && table[c->next].Empty())
		c->next = Next(c->next); 
	}

///////////////////////////////////////////////////////////////////////////////////////////////////
//Remap
///////////////////////////////////////////////////////////////////////////////////////////////////

void Dictionary::Remap()
	{	
	///since remap should be very fast. take more at a time.
	///delay Remap when cookie is there. hard to handle cookie iteration while size changes.
	///remap from bottom up.
	///remap creates two parts of the dict: [0,remap_end] (remap_end, ...]. the former is mixed with old/new entries; the latter contains all new entries.
	///
 	if(num_iterators)
	 	return; 

	int left = DICT_REMAP_ENTRIES;
	while(remap_end >= 0 && left > 0)
		{	
		if(!table[remap_end].Empty() && Remap(remap_end))
			left--;
		else//< successful Remap may increase remap_end in the case of SizeUp due to insert. if so, remap_end need to be worked on again.
			remap_end--;
		}
	if(remap_end < 0)
		remaps = 0; //done remapping. 
	}

bool Dictionary::Remap(int position, int* new_position)
	{
	ASSERT_VALID(this);
	///Remap changes item positions by remove() and insert(). to avoid excessive operation. avoid it when safe iteration is in progress.
 	ASSERT(!cookies || cookies->empty());
	int current = BucketByPosition(position);//current bucket
	int expected = BucketByHash(table[position].hash, log2_buckets); //expected bucket in new table.
	//equal because 1: it's a new item, 2: it's an old item, but new bucket is the same as old. 50% of old items act this way due to fibhash.
	if( current == expected )
		return false;
	DictEntry entry = RemoveAndRelocate(position); // no iteration cookies to adjust, no need for last_affected_position.
	#ifdef DEBUG
	entry.bucket = expected;
	#endif//DEBUG

	//find insert position.
	int insert_position = EndOfClusterByBucket(expected);
	if( new_position )
		*new_position = insert_position;
	entry.distance = insert_position - expected;
	InsertAndRelocate(entry, insert_position);// no iteration cookies to adjust, no need for last_affected_position.
	ASSERT_VALID(this);
	return true;
	}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Iteration
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void* Dictionary::NthEntry(int n, const void*& key, int& key_size) const
	{
		if( !order || n < 0 || n >= Length() )
			return 0;
		DictEntry entry = (*order)[n];
		key = entry.GetKey();
		key_size = entry.key_size;
		return entry.value;	
	}

void Dictionary::MakeRobustCookie(IterCookie* cookie)
	{ //make sure c->next >= 0.
	if( !cookies)
		cookies = new std::vector<IterCookie*>;
	cookie->MakeRobust();
	ASSERT_VALID(cookie);
	}

IterCookie* Dictionary::InitForIterationNonConst() //const
	{
	num_iterators++;
	return new IterCookie(const_cast<Dictionary*>(this));
	}

void Dictionary::StopIterationNonConst(IterCookie* cookie) //const
	{
	ASSERT(num_iterators > 0);
	if(num_iterators > 0)
		num_iterators--;
	delete cookie;
	}

void* Dictionary::NextEntryNonConst(HashKey*& h, IterCookie*& c, int return_hash) //const
	{
	// If there are any inserted entries, return them first.
	// That keeps the list small and helps avoiding searching
	// a large list when deleting an entry.
	ASSERT(c);
	ASSERT_VALID(c);
	if(!table)
		{
		if(num_iterators > 0)
			num_iterators--;
		delete c;
		c = NULL;
		return NULL; //end of iteration.
		}
	if ( c->inserted && !c->inserted->empty() )
		{
		// Return the last one. Order doesn't matter,
		// and removing from the tail is cheaper.
		DictEntry e = c->inserted->back();
		if ( return_hash )
			h = new HashKey(e.GetKey(), e.key_size, e.hash);
		void* v = e.value;
		c->inserted->pop_back();
		return v;
		}

	if( c->next < 0)
		c->next = Next(-1);
	int capacity = Capacity();
	// if resize happens during iteration. before sizeup, c->next points to Capacity(),
	// but now Capacity() doubles up and c->next doesn't point to the end anymore.
	// this is fine because c->next may be filled now.
	// however, c->next can also be empty.
	// before sizeup, we use c->next >= Capacity() to indicate the end of the iteration.
	// now this guard is invalid, we may face c->next is valid but empty now.F
	//fix it here.
	if( c->next < capacity && table[c->next].Empty())
		{
		ASSERT(false); //stop to check the condition here. why it's happening.
		c->next = Next(c->next);
		}
	//filter out visited keys.
	if( c->visited && !c->visited->empty())
		//filter out visited entries.
		while(c->next < capacity )
			{
			ASSERT(!table[c->next].Empty());
			auto it = std::find(c->visited->begin(), c->visited->end(), table[c->next]);
			if( it == c->visited->end())
				break;
			c->visited->erase(it);
			c->next = Next(c->next);
			}

	if( c->next >= capacity )
		{//end.
		if(num_iterators > 0)
			num_iterators--;
		delete c;
		c = NULL;
		return NULL; //end of iteration.
		}

	ASSERT(!table[c->next].Empty());
	void* v = table[c->next].value;
	if ( return_hash )
		h = new HashKey(table[c->next].GetKey(), table[c->next].key_size, table[c->next].hash);
	//prepare for next time.
	c->next = Next(c->next); 	
	ASSERT_VALID(c);
	return v;
	}


IterCookie* Dictionary::InitForIteration() const
{
	Dictionary* dp = const_cast<Dictionary*>(this);
	return dp->InitForIterationNonConst();
}
void* Dictionary::NextEntry(HashKey*& h, IterCookie*& cookie, int return_hash) const
{
	Dictionary* dp = const_cast<Dictionary*>(this);
	return dp->NextEntryNonConst(h,cookie, return_hash);
}
void Dictionary::StopIteration(IterCookie* cookie) const
{
	Dictionary* dp = const_cast<Dictionary*>(this);
	dp->StopIterationNonConst(cookie);
}
