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

void EvoSolution::pollEvoThread(const std::string& transaction_id, std::wstring baseUrl, std::wstring environmentUrl, std::function<void(bool)> callback)
{
	DebugPrint("Starting pollEvoThread()");

	this_thread::sleep_for(chrono::milliseconds(100));

	bool success = false;
	EvoAPI::CheckLoginResponse response;
	while (_runPoll.load())
	{
		EvoAPI evoApi(baseUrl, environmentUrl);

		if (evoApi.CheckLoginRequest(transaction_id.c_str(), response))
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

void EvoSolution::asyncEvoPoll(std::string transaction_id, std::shared_ptr<Configuration> p, std::function<void(bool)> callback)
{
	_runPoll.store(true);
	std::thread t(&EvoSolution::pollEvoThread2, this, transaction_id, p, callback);
	t.detach();
}

void EvoSolution::pollEvoThread2(const std::string& transaction_id, std::shared_ptr<Configuration> p, std::function<void(bool)> callback)
{
	DebugPrint(__FUNCTION__);
	this_thread::sleep_for(chrono::milliseconds(100));

	bool success = false;
	while (_runPoll.load())
	{
		EvoAPI evoapi(p->baseUrl, p->environmentUrl);
		if (evoapi.CheckLoginRequest(transaction_id))
		{
			_runPoll.store(false);
			success = true;
			break;
		}
		this_thread::sleep_for(chrono::milliseconds(500));
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