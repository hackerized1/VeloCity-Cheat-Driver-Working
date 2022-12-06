#pragma once

#define str_len(str) ((sizeof(str) - sizeof(str[0])) / sizeof(str[0]))
#define to_lower(character) ((character >= 'A' && character <= 'Z') ? (character + 32) : character)
#define to_upper(character) ((character >= 'a' && character <= 'z') ? (character - 'a') : character)

template <typename str_type>
bool _strcmp(str_type str1, str_type str2, bool two = true)
{
	if (!str1 || !str2) return false;
	wchar_t c1 = 0, c2 = 0; 
	while (c1 == c2)
	{
		c1 = *str1++; 
		c2 = *str2++;
		c1 = to_lower(c1); 
		c2 = to_lower(c2);
		if (!c1 && (two ? !c2 : 1)) return true;
	} 

	return false;
}