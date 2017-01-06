#pragma once

enum LoaderType
{
    kReflectiveLoader,
    kLoadLibrary
};

inline const char* LoaderTypeToString(LoaderType loaderType)
{
    switch (loaderType)
    {
    case kReflectiveLoader:
        return "ReflectiveLoader";

    case kLoadLibrary:
        return "LoadLibrary";

    default:
        return "Unknown!";
    }
}