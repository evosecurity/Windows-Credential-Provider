#include "pch.h"
#include "EvoSecureString.h"
#include "EvoSolution.h"
#include "../EvoApi/EvoApi.h"
#include "../Configuration.h"
#include <codecvt>
#include <thread>
#include "Logger.h"
	
using namespace std;

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

void EvoSolution::asyncEvoPoll(std::string transaction_id, std::wstring baseUrl, std::wstring environmentUrl, std::function<void(bool)> callback)
{
	_runPoll.store(true);
	std::thread t(&EvoSolution::pollEvoThread, this, transaction_id, baseUrl, environmentUrl, callback);
	t.detach();
}

std::string GetIPAddress()
{
	std::string ipAddress;

	try {
		EvoAPI evoapi(L"https://ifconfig.me");
		evoapi.SetTimeOuts(5000, 5000, 5000);
		auto resp = evoapi.Connect(L"/ip", "", L"GET");
		if (resp.dwStatus == 200)
		{
			ipAddress = resp.sResponse;
		}
	}
	catch (...) {

	}

	return ipAddress;
}

void EvoSolution::pollEvoThread(const std::string& transaction_id, std::wstring baseUrl, std::wstring environmentUrl, std::function<void(bool)> callback)
{
	DebugPrint("Starting pollEvoThread()");

	this_thread::sleep_for(chrono::milliseconds(100));

	std::string ipAddress = GetIPAddress();

	bool success = false;
	EvoAPI::CheckLoginResponse response;
	while (_runPoll.load())
	{
		EvoAPI evoApi(baseUrl, environmentUrl);

		if (evoApi.CheckLoginRequest(transaction_id.c_str(), ipAddress, response))
		{
			_runPoll.store(false);
			success = true;
			break;
		}
		this_thread::sleep_for(chrono::milliseconds(500));
	}

	if (success)
	{
		try
		{
			m_PollResults.data = response.data;
			m_PollResults.iters = response.iters;
			m_PollResults.iv = response.iv;
			m_PollResults.salt = response.salt;
			m_PollResults.offlineCode = response.offlineCode;
			m_PollResults.domain = response.domain;
			callback(response.success);
		}
		catch (...)
		{
			callback(false);
		}
	}


	DebugPrint("Ending pollEvoThread()");
}

void EvoSolution::asyncEvoPoll90(std::string transaction_id, std::shared_ptr<Configuration> p, std::function<void(bool)> callback)
{
	p->SetLastOfflineCode("");
	_runPoll.store(true);
	std::thread t(&EvoSolution::pollEvoThread90, this, transaction_id, p, callback);
	t.detach();
}

void EvoSolution::pollEvoThread90(const std::string& transaction_id, std::shared_ptr<Configuration> p, std::function<void(bool)> callback)
{
	DebugPrint(__FUNCTION__);
	this_thread::sleep_for(chrono::milliseconds(100));
	std::string ipAddress = GetIPAddress();

	bool success = false;
	int its = 0;
	const int max_its = 200;
	while (_runPoll.load())
	{
		EvoAPI::CheckLogin90Response response;
		EvoAPI evoapi(p->baseUrl, p->environmentUrl);
		if (evoapi.CheckLoginRequest(transaction_id, ipAddress, response))
		{
			_runPoll.store(false);
			success = true;
			p->SetLastOfflineCode(response.offline_code);
			break;
		}
		++its;
		if (its >= max_its) {
			break;
		}
		this_thread::sleep_for(chrono::milliseconds(1000));
	}

	if (success)
	{
		callback(true);
	}

	DebugPrint(std::string("Exiting ") + __FUNCTION__);
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

std::string EvoSolution::toLower(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(), ::tolower);
	return s;
}