#include <string>
#include <algorithm>

class EvoStuff
{
public:

	static std::wstring toUpper(std::wstring s)
	{
		std::transform(s.begin(), s.end(), s.begin(), ::toupper);
		return s;
	}
};
