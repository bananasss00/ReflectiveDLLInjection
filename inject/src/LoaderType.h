#pragma once

enum LoaderType
{
    kReflectiveLoader,
    kLoadLibraryW,
    kLoadLibraryA
};

inline const char* LoaderTypeToString(LoaderType loaderType)
{
    switch (loaderType)
    {
    case kReflectiveLoader:
        return "ReflectiveLoader";

    case kLoadLibraryW:
        return "LoadLibraryW";

    case kLoadLibraryA:
        return "LoadLibraryA";

    default:
        return "Unknown!";
    }
}