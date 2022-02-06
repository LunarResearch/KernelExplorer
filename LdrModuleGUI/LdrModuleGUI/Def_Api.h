#ifndef _DEF_API_H_
#define _DEF_API_H_
#pragma once

#include "resource.h"

#define MAX_LOADSTRING 100


/// <summary>
/// Function Definitions
/// </summary>
#ifdef __cplusplus
extern "C" {
#endif
	BOOL Api_InitializationInstance(
		_In_ HINSTANCE hInstance,
		_In_ int nCmdShow
	);

	LRESULT CALLBACK Api_WindowProc(
		_In_ HWND hWnd,
		_In_ UINT message,
		_In_ WPARAM wParam,
		_In_ LPARAM lParam
	);

	INT_PTR CALLBACK Api_AboutBox(
		_In_ HWND hDlg,
		_In_ UINT message,
		_In_ WPARAM wParam,
		_In_opt_ LPARAM lParam
	);

	INT_PTR CALLBACK Api_ServiceSettingManager(
		_In_ HWND hDlg,
		_In_ UINT message,
		_In_ WPARAM wParam,
		_In_opt_ LPARAM lParam
	);

	INT_PTR CALLBACK Api_ProcessSettingManager(
		_In_ HWND hDlg,
		_In_ UINT message,
		_In_ WPARAM wParam,
		_In_opt_ LPARAM lParam
	);

	INT_PTR CALLBACK Api_DeleteFileManager(
		_In_ HWND hDlg,
		_In_ UINT message,
		_In_ WPARAM wParam,
		_In_opt_ LPARAM lParam
	);

	INT_PTR CALLBACK Api_KernelObjectManager(
		_In_ HWND hDlg,
		_In_ UINT message,
		_In_ WPARAM wParam,
		_In_opt_ LPARAM lParam
	);

	DWORD Api_InstallHinfDriver(
		_In_ HWND hWnd,
		_In_ HINSTANCE hInstance
	);

	INT_PTR Api_ZombieProcessManager(
		_In_ HWND hDlg,
		_In_ UINT message,
		_In_ WPARAM wParam,
		_In_opt_ LPARAM lParam
	);

	INT_PTR CALLBACK Api_PropertiesProcessManager(
		HWND hDlg,
		UINT message,
		WPARAM wParam,
		LPARAM lParam
	);

	INT_PTR CALLBACK Api_PropertiesServiceManager(
		HWND hDlg,
		UINT message,
		WPARAM wParam,
		LPARAM lParam
	);


	HWND Api_CreateTabControl(
		_In_ HWND hWnd,				// Parent window (the application's main window)
		_In_ HINSTANCE hInstance	// The global handle to the applicadtion instance
	);

	HWND Api_CreateListView(
		_In_ HWND hWndTab,			// The handle to the control's parent window
		_In_ HINSTANCE hInstance	// The global handle to the applicadtion instance
	);

	HRESULT Api_SizeItemControl(
		_In_ HWND hWndItem,			// Handle of the item control
		_In_ LPARAM lParam			// The lParam parameter of the WM_SIZE message
	);

	BOOL Api_NotifyItemControl(
		_In_ HWND hWndItem,			// Handle of the item control
		_In_ HWND hWndCommItems,	// Handle of the static control
		_In_ HINSTANCE hInstance,	// The global handle to the applicadtion instance
		_In_ LPARAM lParam			// The lParam parameter of the WM_NOTIFY message
	);


	//
	// Creates a child window (a static control) to occupy the tab control's display area. 
	// Returns the handle to the static control. 
	// hWndTab - handle of the tab control. 
	// 
	HWND CreateCommItemsTabControl(
		HWND hWndTab,
		HINSTANCE hInstance
	);


	//
	// SetView: Sets a list-view's window style to change the view.
	// hWndListView: A handle to the list-view control. 
	// dwView:       A value specifying the new view style.
	//
	VOID SetView(
		HWND hWndListView,
		DWORD dwView
	);


	//
	// InitListViewColumns: Adds columns to a list-view control.
	// hWndListView:        Handle to the list-view control. 
	// Returns TRUE if successful, and FALSE otherwise. 
	//
	BOOL InitListViewColumns(
		HWND hWndListView,
		HINSTANCE hInstance
	);

#ifdef __cplusplus
}
#endif

#endif // _DEF_API_H_