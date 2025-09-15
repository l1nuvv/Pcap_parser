#ifndef PCAP_PARSER_CARRAYWRAPPER_H
#define PCAP_PARSER_CARRAYWRAPPER_H

#include <cstddef>   // std::size_t
#include <stdexcept> // std::out_of_range

template<typename T>
class CArrayWrapper {
public:
    explicit CArrayWrapper(std::size_t size) : size_(size), data_(size ? new T[size]() : nullptr) {}

    CArrayWrapper(const CArrayWrapper&)            = delete;
    CArrayWrapper& operator=(const CArrayWrapper&) = delete;

    CArrayWrapper(CArrayWrapper&& other) : size_(other.size_), data_(other.data_)
    {
        other.size_ = 0;
        other.data_ = nullptr;
    }
    CArrayWrapper& operator=(CArrayWrapper&& other)
    {
        if (this != &other)
        {
            delete[] data_;
            size_       = other.size_;
            data_       = other.data_;
            other.size_ = 0;
            other.data_ = nullptr;
        }
        return *this;
    }

    ~CArrayWrapper() { delete[] data_; }

    T& operator[](std::size_t index)
    {
        if (index >= size_) throw std::out_of_range("Index out of bounds");
        return data_[index];
    }
    const T& operator[](std::size_t index) const
    {
        if (index >= size_) throw std::out_of_range("Index out of bounds");
        return data_[index];
    }

    std::size_t size() const { return size_; }

    T*       raw_data() { return data_; }
    const T* raw_data() const { return data_; }

private:
    std::size_t size_{0};
    T*          data_{nullptr};
};
#endif // PCAP_PARSER_CARRAYWRAPPER_H
