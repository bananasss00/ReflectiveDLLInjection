#pragma once

enum InjectType
{
    kCreateRemoteThread,
    kSetThreadContext,
    kQueueUserAPC
};

inline const char* InjectTypeToString(InjectType injectType)
{
    switch (injectType)
    {
    case kCreateRemoteThread:
        return "CreateRemoteThread";

    case kSetThreadContext:
        return "SetThreadContext";

    case kQueueUserAPC:
        return "QueueUserAPC";

    default:
        return "Unknown!";
    }
}
