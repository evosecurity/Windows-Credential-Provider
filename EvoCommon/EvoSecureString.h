#pragma once

/*

This string comes from an Open SSL example. It seems to be more complete than the privacyIDEA example.
I made one change to this string. Since we are on Windows, I replaced OPENSSL_cleanse() with SecureZeroMemory()

*/

#include <string>
#include <memory>

#ifdef max
#undef max
#endif max

template <typename T>
struct zallocator
{
public:
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

    pointer address(reference v) const { return &v; }
    const_pointer address(const_reference v) const { return &v; }

    pointer allocate(size_type n, const void* hint = 0) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer> (::operator new (n * sizeof(value_type)));
    }

    void deallocate(pointer p, size_type n) {
        // OPENSSL_cleanse(p, n * sizeof(T));
        SecureZeroMemory(p, n * sizeof(T));
        ::operator delete(p);
    }

    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof(T);
    }

    template<typename U>
    struct rebind
    {
        typedef zallocator<U> other;
    };

    void construct(pointer ptr, const T& val) {
        new (static_cast<T*>(ptr)) T(val);
    }

    void destroy(pointer ptr) {
        static_cast<T*>(ptr)->~T();
    }

    template<typename U, typename... Args>
    void construct(U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr)) U(std::forward<Args>(args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }

    template <typename U>
    friend bool operator==(const zallocator<T>& a, const zallocator<U>& b)
    {
        return true;
    }
    template <typename U>
    friend bool operator!=(const zallocator<T>& a, const zallocator<U>& b)
    {
        return false;
    }

    constexpr zallocator() noexcept = default;
    template< class U>
    constexpr zallocator(const zallocator<U>& other) noexcept
    {
    }
};

using secure_string = std::basic_string<char, std::char_traits<char>, zallocator<char> >;
using secure_wstring = std::basic_string<wchar_t, std::char_traits<wchar_t>, zallocator<wchar_t> >;

using SecureString = secure_string;
using SecureWString = secure_wstring;
