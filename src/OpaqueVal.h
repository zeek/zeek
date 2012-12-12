#ifndef OPAQUEVAL_H
#define OPAQUEVAL_H

#include "Val.h"
#include "digest.h"

class HashVal : public OpaqueVal {
public:
  virtual bool IsValid() const;
  virtual bool Init();
  virtual bool Feed(const void* data, size_t size);
  virtual StringVal* Get();

protected:
  HashVal() { };
  HashVal(OpaqueType* t);
  virtual bool Update(const void* data, size_t size);
  virtual StringVal* Finish();

  DECLARE_SERIAL(HashVal);

private:
  // This flag exists because Get() can only be called once.
  bool valid;
};

class MD5Val : public HashVal {
public:
  static void digest(val_list& vlist, u_char result[MD5_DIGEST_LENGTH]);

  static void hmac(val_list& vlist,
                   u_char key[MD5_DIGEST_LENGTH],
                   u_char result[MD5_DIGEST_LENGTH]);

  MD5Val() : HashVal(new OpaqueType("md5")) { }

protected:
  friend class Val;

  virtual bool Init() /* override */;
  virtual bool Update(const void* data, size_t size) /* override */;
  virtual StringVal* Finish() /* override */;

  DECLARE_SERIAL(MD5Val);

private:
  MD5_CTX ctx;
};

class SHA1Val : public HashVal {
public:
  SHA1Val() : HashVal(new OpaqueType("sha1")) { }

protected:
  friend class Val;

  virtual bool Init() /* override */;
  virtual bool Update(const void* data, size_t size) /* override */;
  virtual StringVal* Finish() /* override */;

  DECLARE_SERIAL(SHA1Val);

private:
  SHA_CTX ctx;
};

class SHA256Val : public HashVal {
public:
  SHA256Val() : HashVal(new OpaqueType("sha256")) { }

protected:
  friend class Val;

  virtual bool Init() /* override */;
  virtual bool Update(const void* data, size_t size) /* override */;
  virtual StringVal* Finish() /* override */;

  DECLARE_SERIAL(SHA256Val);

private:
  SHA256_CTX ctx;
};

#endif
