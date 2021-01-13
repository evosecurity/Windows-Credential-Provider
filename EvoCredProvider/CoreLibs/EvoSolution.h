#pragma once

#include "../EvoConf.h"
#include "Challenge.h"
#include "EvoSecureString.h"
#include <functional>
#include <atomic>

class EvoSolution
{
public:
	static std::string ws2s(const std::wstring& ws);
	static std::wstring toUpperCase(std::wstring s);
	static std::wstring s2ws(const std::string& s);

	HRESULT validateCheck(const std::wstring& username, const std::wstring& domain, const SecureWString& otp, const std::string& transaction_id = std::string());

	const EvoSolution& operator=(const EvoSolution&) = delete;

	void Initialize(PICONFIG conf);

	Challenge getCurrentChallenge();


	// Poll for the given transaction asynchronously. When polling returns success, the transaction is finalized
	// according to https://privacyidea.readthedocs.io/en/latest/configuration/authentication_modes.html#outofband-mode
	// After that, the callback function is called with the result
	void asyncPollTransaction(std::string username, std::string transaction_id, std::function<void(bool)> callback);


	int getLastError();
	std::wstring getLastErrorMessage();

	bool stopPoll();

private:

	void pollThread(const std::string& transaction_id, const std::string& username, std::function<void(bool)> callback);

	std::atomic<bool> _runPoll = false;

	Challenge _currentChallenge;

	int _lastError = 0;
	std::string _lastErrorMessage;


};


