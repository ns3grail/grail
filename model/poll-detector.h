/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

/*
 * A very simple poll detection heuristic that causes exponentially growing system call processing times as long as consecutive, "qualifying" system calls are detected. 
 * The qualifying calls are gettimeofday(2) and select(2).
 * More acurate strategies are desireable, but this variant proved quite useful already.
 * Note that the maximum, exponential delay is set to 1ms here, which might be too much for some applications.
 */

#include "grail.h"
#include "ns3/log.h"
#include "ptrace-utils.h"

#include <cmath>
#include <vector>

namespace ns3
{
  template<class DetectionStrategy, class BackoffStrategy> class PollLoopDetector
  {
  public:
    Time HandleSystemCall(pid_t pid, int syscall) {
      bool isInPollLoop = detector(pid,syscall);
      return strategy(isInPollLoop);
    }

    const Time GetDelay() const {
      return strategy.GetDelay();
    }

  private:
    DetectionStrategy detector;
    BackoffStrategy   strategy;
  };

  // exponentially increasing delay, up to 1ms
  class ExponentialBackoffStrategy
  {
  public:
    ExponentialBackoffStrategy()
      :pollSteps(0)
      {}
    Time operator()(bool inLoop) {
      if (!inLoop) {
        pollSteps = 0;
        return GetDelay();
      } else {
        pollSteps += 1;
        return GetDelay();
      }
    }

    const Time GetDelay() const {
      // maximum of 1ms
      return ( pollSteps == 0 ? Seconds(0.0) : std::max(1.0,std::min(std::pow(2.0,pollSteps),10000.0)) * NanoSeconds(100) );
    }
  private:
    uint32_t pollSteps;
  };

  class SimpleGettimeofdaySelectLoopDetector
  {
  public:
    SimpleGettimeofdaySelectLoopDetector()
      :previousCallQualified(false)
    {}
    bool operator()(pid_t pid, int syscall) {
      bool thisCallQualifies;
      if(syscall == SYS_gettimeofday) {
        thisCallQualifies = true;
      } else if(syscall == SYS_select) {
        thisCallQualifies = true;
      } else {
        thisCallQualifies = false;
      }

      bool result = previousCallQualified && thisCallQualifies;
      previousCallQualified = thisCallQualifies;
      return result;
    }
  private:
    bool previousCallQualified;
  };
}
