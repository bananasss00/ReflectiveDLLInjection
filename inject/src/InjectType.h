#pragma once

enum InjectType
{
    kCreateRemoteThread,
    kChangeThreadEntryPoint,
    kSetThreadContext,
    kQueueUserAPC,
    kNtQueueApcThread,
    kNtQueueApcThreadEx
};

inline const char* InjectTypeToString(InjectType injectType)
{
    switch (injectType)
    {
    case kCreateRemoteThread:
        return "CreateRemoteThread";

    case kChangeThreadEntryPoint:
        return "ChangeThreadEntryPoint";

    case kSetThreadContext:
        return "SetThreadContext";

    case kQueueUserAPC:
        return "QueueUserAPC";

    case kNtQueueApcThread:
        return "NtQueueApcThread";

    case kNtQueueApcThreadEx:
        return "NtQueueApcThreadEx";

    default:
        return "Unknown!";
    }
}
