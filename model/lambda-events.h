/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

/* Disclaimer: Written by Craig Dowell and posted on the ns-3 mailing list
   for inclusion at http://mailman.isi.edu/pipermail/ns-developers/2015-October/013238.html
*/

#ifndef MAKE_FUNCTIONAL_EVENT_H
#define MAKE_FUNCTIONAL_EVENT_H

#include <ns3/event-impl.h>

namespace ns3 {

  template <typename T>
  Ptr<EventImpl> MakeFunctionalEvent (T function)
  {
    class EventMemberImplFunctional : public EventImpl
    {
    public:
      EventMemberImplFunctional (T function)
        : m_function (function)
      {
      }
      virtual ~EventMemberImplFunctional ()
      {
      }
    private:
      virtual void Notify (void)
      {
        m_function();
      }
      T m_function;
    };
    Ptr<EventMemberImplFunctional> ev = Create<EventMemberImplFunctional> (function);
    return ev;
  }

} // namespace ns3

#endif /* MAKE_FUNCTIONAL_EVENT_H */
