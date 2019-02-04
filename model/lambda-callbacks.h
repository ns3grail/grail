/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#ifndef __LAMBDA_CALLBACKS_H__
#define __LAMBDA_CALLBACKS_H__

#include <functional>

namespace ns3 {
  template<typename T>
    static bool operator!=(const std::function<T>& f1,const std::function<T>& f2)
    {
      return &f1 != &f2;
    }

  template<typename R,typename ...Args>
    Callback<R,Args...> MakeFunctionCallback(const std::function<R(Args...)>& f)
    {
      return Callback<R,Args...>(f,true,true);
    }
}

#endif
