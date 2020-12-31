#include "pch.h"
#include "SecureString.h"
#include "EvoSolution.h"
#include <codecvt>
#include <thread>
#include "Logger.h"


void EvoSolution::Initialize(PICONFIG conf)
{

}

HRESULT EvoSolution::validateCheck(const std::wstring& username, const std::wstring& domain, const SecureWString& otp, const std::string& transaction_id)
{
	return E_FAIL;
}

Challenge EvoSolution::getCurrentChallenge()
{
	return _currentChallenge;
}

void EvoSolution::asyncPollTransaction(std::string username, std::string transaction_id, std::function<void(bool)> callback)
{
	_runPoll.store(true);
	std::thread t(&EvoSolution::pollThread, this, transaction_id, username, callback);
	t.detach();
}


void EvoSolution::pollThread(const std::string& transaction_id, const std::string& username, std::function<void(bool)> callback)
{
	callback(false);
}

bool EvoSolution::stopPoll()
{
	DebugPrint("Stopping poll thread...");
	_runPoll.store(false);
	return true;
}

int EvoSolution::getLastError()
{
	return _lastError;
}

std::wstring EvoSolution::getLastErrorMessage()
{
	return s2ws(_lastErrorMessage);
}


std::string EvoSolution::ws2s(const std::wstring& ws)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(ws);

}

std::wstring EvoSolution::toUpperCase(std::wstring s)
{
	std::transform(s.begin(), s.end(), s.begin(), ::toupper);
	return s;
}

std::wstring EvoSolution::s2ws(const std::string& s)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(s);
}