
#ifndef __HTTP_QUIC_CLIENT_ACCEPT_H__
#define __HTTP_QUIC_CLIENT_ACCEPT_H__

#include "ts/ink_platform.h"
#include "I_Net.h"

// XXX HttpSessionAccept::Options needs to be refactored and separated from HttpSessionAccept so that
// it can generically apply to all protocol implementations.
#include "http/HttpSessionAccept.h"

class HQClientAccept : public SessionAccept
{
public:
  explicit HQClientAccept(const HttpSessionAccept::Options &);
  ~HQClientAccept();

  int mainEvent(int event, void *data);
  bool accept(NetVConnection *netvc, MIOBuffer *iobuf, IOBufferReader *reader);

private:
  HQClientAccept(const HQClientAccept &);
  HQClientAccept &operator=(const HQClientAccept &);

  HttpSessionAccept::Options options;
};

#endif
