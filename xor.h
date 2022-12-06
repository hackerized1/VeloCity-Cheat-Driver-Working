#pragma once

constexpr unsigned long long gen_lin_congruent(unsigned rounds)
{
    return 1013904223ull + (1664525ull * ((rounds > 0) ? gen_lin_congruent(rounds - 1) : (6773))) % 0xFFFFFFFF;
}

#define gen_rand_num(min, max) (min + (gen_lin_congruent(10) % (max - min + 1)))

constexpr const unsigned long long XORKEY = gen_rand_num(0, 0xFF);

template<typename Char >
constexpr Char encrypt_character(const Char character, int index)
{
    return static_cast<Char>(character ^ (static_cast<Char>(XORKEY) + index));
}

template <unsigned size, typename Char>
class cXorStr
{
public:
    const unsigned _nb_chars = (size - 1);
    Char _string[size];

    inline constexpr cXorStr(const Char* string) : _string{}
    {
        for (unsigned i = 0u; i < size; ++i)
            _string[i] = encrypt_character<Char>(string[i], i);
    }

    const Char* decrypt() const
    {
        Char* string = const_cast<Char*>(_string);
        for (unsigned t = 0; t < _nb_chars; t++)
        {
            string[t] = static_cast<Char>(string[t] ^ (static_cast<Char>(XORKEY) + t));
        }
        string[_nb_chars] = '\0';
        return string;
    }
};

#define e(str) []{ constexpr cXorStr<(sizeof(str)/sizeof(char)), char> expr(str); return expr; }().decrypt()
