#include "P_Net.h"

#include "HQClientAccept.h"
#include "quic/QUICEvents.h"
#include "Http1ClientSession.h"

bool
HQClientAccept::accept(NetVConnection *netvc, MIOBuffer *iobuf, IOBufferReader *reader)
{
  Http1ClientSession *new_session = THREAD_ALLOC_INIT(http1ClientSessionAllocator, this_ethread());
  new_session->new_connection(netvc, iobuf, reader, false);
  return true;
}

int
HQClientAccept::mainEvent(int event, void *data)
{
  NetVConnection *netvc;
  ink_release_assert(event == QUIC_EVENT_NEW_STREAM || event == QUIC_EVENT_CLOSING_CONNECTION);
  ink_release_assert((event == QUIC_EVENT_NEW_STREAM) ? (data != nullptr) : (1));

  if (event == QUIC_EVENT_NEW_STREAM) {
    netvc = static_cast<NetVConnection *>(data);
    if (!this->accept(netvc, nullptr, nullptr)) {
      netvc->do_io_close();
    }
    return EVENT_CONT;
  } else {
    // QUIC_EVENT_CLOSING_CONNECTION;
    delete this;
  }

  return EVENT_CONT;
}
