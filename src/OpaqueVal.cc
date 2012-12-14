#include "OpaqueVal.h"
#include "Reporter.h"
#include "Serializer.h"

bool HashVal::IsValid() const
  {
  return valid;
  }

bool HashVal::Init()
  {
  if ( valid )
    return false;

  valid = DoInit();
  return valid;
  }

StringVal* HashVal::Get()
  {
  if ( ! valid )
    return new StringVal("");

  StringVal* result = DoGet();
  valid = false;
  return result;
  }

bool HashVal::Feed(const void* data, size_t size)
  {
  if ( valid )
    return DoFeed(data, size);

  reporter->InternalError("invalid opaque hash value");
  return false;
  }

bool HashVal::DoInit()
  {
  assert(! "missing implementation of DoInit()");
  return false;
  }

bool HashVal::DoFeed(const void*, size_t)
  {
  assert(! "missing implementation of DoFeed()");
  return false;
  }

StringVal* HashVal::DoGet()
  {
  assert(! "missing implementation of DoGet()");
  return new StringVal("");
  }

HashVal::HashVal(OpaqueType* t) : OpaqueVal(t), valid(false) { }

IMPLEMENT_SERIAL(HashVal, SER_HASH_VAL);

bool HashVal::DoSerialize(SerialInfo* info) const
  {
  DO_SERIALIZE(SER_HASH_VAL, OpaqueVal);
  return SERIALIZE(valid);
  }

bool HashVal::DoUnserialize(UnserialInfo* info)
  {
  DO_UNSERIALIZE(OpaqueVal);
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

bool MD5Val::DoInit()
  {
  assert(! IsValid());
  md5_init(&ctx);
  return true;
  }

bool MD5Val::DoFeed(const void* data, size_t size)
  {
  if ( ! IsValid() )
    return new StringVal("");

  md5_update(&ctx, data, size);
  return true;
  }

StringVal* MD5Val::DoGet()
  {
  if ( ! IsValid() )
    return new StringVal("");

  u_char digest[MD5_DIGEST_LENGTH];
  md5_final(&ctx, digest);
  return new StringVal(md5_digest_print(digest));
  }

IMPLEMENT_SERIAL(MD5Val, SER_MD5_VAL);

bool MD5Val::DoSerialize(SerialInfo* info) const
  {
  DO_SERIALIZE(SER_MD5_VAL, HashVal);

  if ( ! IsValid() )
    return true;

  if ( ! SERIALIZE(ctx.A) )
    return false;
  if ( ! SERIALIZE(ctx.B) )
    return false;
  if ( ! SERIALIZE(ctx.C) )
    return false;
  if ( ! SERIALIZE(ctx.D) )
    return false;
  if ( ! SERIALIZE(ctx.Nl) )
    return false;
  if ( ! SERIALIZE(ctx.Nh) )
    return false;
  for ( int i = 0; i < MD5_LBLOCK; ++i )
    if ( ! SERIALIZE(ctx.data[i]) )
      return false;
  if ( ! SERIALIZE(ctx.num) )
    return false;

  return true;
  }

bool MD5Val::DoUnserialize(UnserialInfo* info)
  {
  DO_UNSERIALIZE(HashVal);

  if (! IsValid())
    return true;

  if ( ! UNSERIALIZE(&ctx.A) )
    return false;
  if ( ! UNSERIALIZE(&ctx.B) )
    return false;
  if ( ! UNSERIALIZE(&ctx.C) )
    return false;
  if ( ! UNSERIALIZE(&ctx.D) )
    return false;
  if ( ! UNSERIALIZE(&ctx.Nl) )
    return false;
  if ( ! UNSERIALIZE(&ctx.Nh) )
    return false;
  for ( int i = 0; i < MD5_LBLOCK; ++i )
    if ( ! UNSERIALIZE(&ctx.data[i]) )
      return false;
  if ( ! UNSERIALIZE(&ctx.num) )
    return false;

  return true;
  }


void SHA1Val::digest(val_list& vlist, u_char result[SHA_DIGEST_LENGTH])
  {
  SHA_CTX h;
  sha1_init(&h);
  loop_over_list(vlist, i)
    {
    Val* v = vlist[i];
    if ( v->Type()->Tag() == TYPE_STRING )
      {
      const BroString* str = v->AsString();
      sha1_update(&h, str->Bytes(), str->Len());
      }
    else
      {
      ODesc d(DESC_BINARY);
      v->Describe(&d);
      sha1_update(&h, (const u_char *) d.Bytes(), d.Len());
      }
    }
  sha1_final(&h, result);
  }

bool SHA1Val::DoInit()
  {
  assert(! IsValid());
  sha1_init(&ctx);
  return true;
  }

bool SHA1Val::DoFeed(const void* data, size_t size)
  {
  if ( ! IsValid() )
    return new StringVal("");

  sha1_update(&ctx, data, size);
  return true;
  }

StringVal* SHA1Val::DoGet()
  {
  if ( ! IsValid() )
    return new StringVal("");

  u_char digest[SHA_DIGEST_LENGTH];
  sha1_final(&ctx, digest);
  return new StringVal(sha1_digest_print(digest));
  }

IMPLEMENT_SERIAL(SHA1Val, SER_SHA1_VAL);

bool SHA1Val::DoSerialize(SerialInfo* info) const
  {
  DO_SERIALIZE(SER_SHA1_VAL, HashVal);

  if ( ! IsValid() )
    return true;

  if ( ! SERIALIZE(ctx.h0) )
    return false;
  if ( ! SERIALIZE(ctx.h1) )
    return false;
  if ( ! SERIALIZE(ctx.h2) )
    return false;
  if ( ! SERIALIZE(ctx.h3) )
    return false;
  if ( ! SERIALIZE(ctx.h4) )
    return false;
  if ( ! SERIALIZE(ctx.Nl) )
    return false;
  if ( ! SERIALIZE(ctx.Nh) )
    return false;
  for ( int i = 0; i < SHA_LBLOCK; ++i )
    if ( ! SERIALIZE(ctx.data[i]) )
      return false;
  if ( ! SERIALIZE(ctx.num) )
    return false;

  return true;
  }

bool SHA1Val::DoUnserialize(UnserialInfo* info)
  {
  DO_UNSERIALIZE(HashVal);

  if ( ! IsValid() )
    return true;

  if ( ! UNSERIALIZE(&ctx.h0) )
    return false;
  if ( ! UNSERIALIZE(&ctx.h1) )
    return false;
  if ( ! UNSERIALIZE(&ctx.h2) )
    return false;
  if ( ! UNSERIALIZE(&ctx.h3) )
    return false;
  if ( ! UNSERIALIZE(&ctx.h4) )
    return false;
  if ( ! UNSERIALIZE(&ctx.Nl) )
    return false;
  if ( ! UNSERIALIZE(&ctx.Nh) )
    return false;
  for ( int i = 0; i < SHA_LBLOCK; ++i )
    if ( ! UNSERIALIZE(&ctx.data[i]) )
      return false;
  if ( ! UNSERIALIZE(&ctx.num) )
    return false;

  return true;
  }


void SHA256Val::digest(val_list& vlist, u_char result[SHA256_DIGEST_LENGTH])
  {
  SHA256_CTX h;
  sha256_init(&h);
  loop_over_list(vlist, i)
    {
    Val* v = vlist[i];
    if ( v->Type()->Tag() == TYPE_STRING )
      {
      const BroString* str = v->AsString();
      sha256_update(&h, str->Bytes(), str->Len());
      }
    else
      {
      ODesc d(DESC_BINARY);
      v->Describe(&d);
      sha256_update(&h, (const u_char *) d.Bytes(), d.Len());
      }
    }
  sha256_final(&h, result);
  }

bool SHA256Val::DoInit()
  {
  assert( ! IsValid() );
  sha256_init(&ctx);
  return true;
  }

bool SHA256Val::DoFeed(const void* data, size_t size)
  {
  if ( ! IsValid() )
    return new StringVal("");

  sha256_update(&ctx, data, size);
  return true;
  }

StringVal* SHA256Val::DoGet()
  {
  if ( ! IsValid() )
    return new StringVal("");

  u_char digest[SHA256_DIGEST_LENGTH];
  sha256_final(&ctx, digest);
  return new StringVal(sha256_digest_print(digest));
  }

IMPLEMENT_SERIAL(SHA256Val, SER_SHA256_VAL);

bool SHA256Val::DoSerialize(SerialInfo* info) const
  {
  DO_SERIALIZE(SER_SHA256_VAL, HashVal);

  if ( ! IsValid() )
    return true;

  for ( int i = 0; i < 8; ++i )
    if ( ! SERIALIZE(ctx.h[i]) )
      return false;
  if ( ! SERIALIZE(ctx.Nl) )
    return false;
  if ( ! SERIALIZE(ctx.Nh) )
    return false;
  for ( int i = 0; i < SHA_LBLOCK; ++i )
    if ( ! SERIALIZE(ctx.data[i]) )
      return false;
  if ( ! SERIALIZE(ctx.num) )
    return false;
  if ( ! SERIALIZE(ctx.md_len) )
    return false;

  return true;
  }

bool SHA256Val::DoUnserialize(UnserialInfo* info)
  {
  DO_UNSERIALIZE(HashVal);

  if ( ! IsValid() )
    return true;

  for ( int i = 0; i < 8; ++i )
    if ( ! UNSERIALIZE(&ctx.h[i]) )
      return false;
  if ( ! UNSERIALIZE(&ctx.Nl) )
    return false;
  if ( ! UNSERIALIZE(&ctx.Nh) )
    return false;
  for ( int i = 0; i < SHA_LBLOCK; ++i )
    if ( ! UNSERIALIZE(&ctx.data[i]) )
      return false;
  if ( ! UNSERIALIZE(&ctx.num) )
    return false;
  if ( ! UNSERIALIZE(&ctx.md_len) )
    return false;

  return true;
  }


bool EntropyVal::Feed(const void* data, size_t size)
  {
  state.add(data, size);
  return true;
  }

bool EntropyVal::Get(double *r_ent, double *r_chisq, double *r_mean,
                     double *r_montepicalc, double *r_scc)
  {
  state.end(r_ent, r_chisq, r_mean, r_montepicalc, r_scc);
  return true;
  }

IMPLEMENT_SERIAL(EntropyVal, SER_ENTROPY_VAL);

bool EntropyVal::DoSerialize(SerialInfo* info) const
  {
  DO_SERIALIZE(SER_ENTROPY_VAL, OpaqueVal);

  for ( int i = 0; i < 256; ++i )
    if ( ! SERIALIZE(state.ccount[i]) )
      return false;
  if ( ! SERIALIZE(state.totalc) )
    return false;
  if ( ! SERIALIZE(state.mp) )
    return false;
  if ( ! SERIALIZE(state.sccfirst) )
    return false;
  for ( int i = 0; i < RT_MONTEN; ++i )
    if ( ! SERIALIZE(state.monte[i]) )
      return false;
  if ( ! SERIALIZE(state.inmont) )
    return false;
  if ( ! SERIALIZE(state.mcount) )
    return false;
  if ( ! SERIALIZE(state.cexp) )
    return false;
  if ( ! SERIALIZE(state.montex) )
    return false;
  if ( ! SERIALIZE(state.montey) )
    return false;
  if ( ! SERIALIZE(state.montepi) )
    return false;
  if ( ! SERIALIZE(state.sccu0) )
    return false;
  if ( ! SERIALIZE(state.scclast) )
    return false;
  if ( ! SERIALIZE(state.scct1) )
    return false;
  if ( ! SERIALIZE(state.scct2) )
    return false;
  if ( ! SERIALIZE(state.scct3) )
    return false;

  return true;
  }

bool EntropyVal::DoUnserialize(UnserialInfo* info)
  {
  DO_UNSERIALIZE(OpaqueVal);

  for ( int i = 0; i < 256; ++i )
    if ( ! UNSERIALIZE(&state.ccount[i]) )
      return false;
  if ( ! UNSERIALIZE(&state.totalc) )
    return false;
  if ( ! UNSERIALIZE(&state.mp) )
    return false;
  if ( ! UNSERIALIZE(&state.sccfirst) )
    return false;
  for ( int i = 0; i < RT_MONTEN; ++i )
    if ( ! UNSERIALIZE(&state.monte[i]) )
      return false;
  if ( ! UNSERIALIZE(&state.inmont) )
    return false;
  if ( ! UNSERIALIZE(&state.mcount) )
    return false;
  if ( ! UNSERIALIZE(&state.cexp) )
    return false;
  if ( ! UNSERIALIZE(&state.montex) )
    return false;
  if ( ! UNSERIALIZE(&state.montey) )
    return false;
  if ( ! UNSERIALIZE(&state.montepi) )
    return false;
  if ( ! UNSERIALIZE(&state.sccu0) )
    return false;
  if ( ! UNSERIALIZE(&state.scclast) )
    return false;
  if ( ! UNSERIALIZE(&state.scct1) )
    return false;
  if ( ! UNSERIALIZE(&state.scct2) )
    return false;
  if ( ! UNSERIALIZE(&state.scct3) )
    return false;

  return true;
  }
