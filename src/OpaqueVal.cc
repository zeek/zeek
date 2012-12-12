#include "OpaqueVal.h"
#include "Reporter.h"
#include "Serializer.h"

bool HashVal::IsValid() const
  {
  return valid;
  }

bool HashVal::Init()
  {
  assert(! "missing implementation of Init()");
  return false;
  }

StringVal* HashVal::Get()
  {
  if ( ! valid )
    return new StringVal("");

  StringVal* result = Finish();
  valid = false;
  return result;
  }

bool HashVal::Feed(const void* data, size_t size)
  {
  if ( valid )
    return Update(data, size);

  reporter->InternalError("invalidated opaque handle");
	return false;
  }

bool HashVal::Update(const void*, size_t)
  {
  assert(! "missing implementation of Update()");
  return false;
  }

StringVal* HashVal::Finish()
  {
  assert(! "missing implementation of Finish()");
  return new StringVal("");
  }

HashVal::HashVal(OpaqueType* t) : OpaqueVal(t), valid(true) { }

IMPLEMENT_SERIAL(HashVal, SER_HASH_VAL);

bool HashVal::DoSerialize(SerialInfo* info) const
  {
  return SERIALIZE(valid);
  }

bool HashVal::DoUnserialize(UnserialInfo* info)
  {
  return UNSERIALIZE(&valid);
  }


void MD5Val::digest(val_list& vlist, u_char result[MD5_DIGEST_LENGTH])
	{
	MD5_CTX h;

	md5_init(&h);
	loop_over_list(vlist, i)
		{
		Val* v = vlist[i];
		if ( v->Type()->Tag() == TYPE_STRING )
			{
			const BroString* str = v->AsString();
			md5_update(&h, str->Bytes(), str->Len());
			}
		else
			{
			ODesc d(DESC_BINARY);
			v->Describe(&d);
			md5_update(&h, (const u_char *) d.Bytes(), d.Len());
			}
		}
	md5_final(&h, result);
	}

void MD5Val::hmac(val_list& vlist,
                  u_char key[MD5_DIGEST_LENGTH],
                  u_char result[MD5_DIGEST_LENGTH])
	{
	digest(vlist, result);
	for ( int i = 0; i < MD5_DIGEST_LENGTH; ++i )
		result[i] ^= key[i];
	MD5(result, MD5_DIGEST_LENGTH, result);
	}

bool MD5Val::Init()
  {
  md5_init(&ctx);
  return true;
  }

bool MD5Val::Update(const void* data, size_t size)
  {
  assert(IsValid());
  md5_update(&ctx, data, size);
  return true;
  }

StringVal* MD5Val::Finish()
  {
  assert(IsValid());
  u_char digest[MD5_DIGEST_LENGTH];
  md5_final(&ctx, digest);
  return new StringVal(md5_digest_print(digest));
  }

IMPLEMENT_SERIAL(MD5Val, SER_MD5_VAL);

bool MD5Val::DoSerialize(SerialInfo* info) const
  {
  // TODO: Implement serialization of MD5 state.
  return false;
  }

bool MD5Val::DoUnserialize(UnserialInfo* info)
  {
  // TODO: Implement deserialization of MD5 state.
  return false;
  }


bool SHA1Val::Init()
  {
  sha1_init(&ctx);
  return true;
  }

bool SHA1Val::Update(const void* data, size_t size)
  {
  assert(IsValid());
  sha1_update(&ctx, data, size);
  return true;
  }

StringVal* SHA1Val::Finish()
  {
  assert(IsValid());
  u_char digest[SHA_DIGEST_LENGTH];
  sha1_final(&ctx, digest);
  return new StringVal(sha1_digest_print(digest));
  }

IMPLEMENT_SERIAL(SHA1Val, SER_SHA1_VAL);

bool SHA1Val::DoSerialize(SerialInfo* info) const
  {
  // TODO: Implement serialization of SHA1 state.
  return false;
  }

bool SHA1Val::DoUnserialize(UnserialInfo* info)
  {
  // TODO: Implement deserialization of SHA1 state.
  return false;
  }


bool SHA256Val::Init()
  {
  sha256_init(&ctx);
  return true;
  }

bool SHA256Val::Update(const void* data, size_t size)
  {
  assert(IsValid());
  sha256_update(&ctx, data, size);
  return true;
  }

StringVal* SHA256Val::Finish()
  {
  assert(IsValid());
  u_char digest[SHA256_DIGEST_LENGTH];
  sha256_final(&ctx, digest);
  return new StringVal(sha256_digest_print(digest));
  }

IMPLEMENT_SERIAL(SHA256Val, SER_SHA256_VAL);

bool SHA256Val::DoSerialize(SerialInfo* info) const
  {
  // TODO: Implement serialization of SHA256 state.
  return false;
  }

bool SHA256Val::DoUnserialize(UnserialInfo* info)
  {
  // TODO: Implement deserialization of SHA256 state.
  return false;
  }
