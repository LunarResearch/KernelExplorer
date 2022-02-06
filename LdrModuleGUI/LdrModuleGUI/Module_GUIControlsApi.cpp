#include "Def_Sys.h"
#include "Def_Api.h"


HWND Api_CreateTabControl(_In_ HWND hWnd, _In_ HINSTANCE hInstance)
{
    INITCOMMONCONTROLSEX icex{ sizeof(INITCOMMONCONTROLSEX) };
    icex.dwICC = ICC_TAB_CLASSES;
    InitCommonControlsEx(&icex);

    RECT rc{};
    GetClientRect(hWnd, &rc);

    auto hWndTab = CreateWindow(WC_TABCONTROL, _TEXT(""), WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, NULL, NULL, rc.right, rc.bottom, hWnd, nullptr, hInstance, nullptr);
    if (hWndTab == nullptr) {
        return nullptr;
    }

    _TCHAR achTemp[MAX_PATH];
    TCITEM tie{};
    tie.mask = TCIF_TEXT | TCIF_IMAGE;
    tie.iImage = -1;
    tie.pszText = achTemp;

    for (int i = 0; i < 2; i++) {
        LoadString(hInstance, ID_TAB_PROCESS + i, achTemp, sizeof(achTemp) / sizeof(achTemp[0]));
        if (TabCtrl_InsertItem(hWndTab, i, &tie) == -1) {
            DestroyWindow(hWndTab);
            return nullptr;
        }
    }

    return hWndTab;
}

HWND Api_CreateListView(_In_ HWND hWndTab, _In_ HINSTANCE hInstance)
{
    INITCOMMONCONTROLSEX icex{ sizeof(INITCOMMONCONTROLSEX) };
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    RECT rc{};
    GetClientRect(hWndTab, &rc);

    auto hWndListView = CreateWindow(WC_LISTVIEW, _TEXT(""), WS_CHILD | LVS_REPORT | LVS_EDITLABELS, NULL, NULL,
        rc.right - rc.left, rc.bottom - rc.top, hWndTab, nullptr /*(HMENU)IDM_CODE_SAMPLES*/, hInstance, nullptr);

    return hWndListView;
}

HRESULT Api_SizeItemControl(_In_ HWND hWndItem, _In_ LPARAM lParam)
{
    RECT rc{};

    if (hWndItem == nullptr) return E_INVALIDARG;
    if (!SetWindowPos(hWndItem, HWND_TOP, NULL, NULL, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), SWP_SHOWWINDOW)) return E_FAIL;

    return S_OK;
}

BOOL Api_NotifyItemControl(_In_ HWND hWndItem, _In_ HWND hWndCommItems, _In_ HINSTANCE hInstance, _In_ LPARAM lParam)
{
    _TCHAR achTemp[256];

    switch (((LPNMHDR)lParam)->code)
    {
    case TCN_SELCHANGING:
        return FALSE;

    case TCN_SELCHANGE:
        auto iPage = TabCtrl_GetCurSel(hWndItem);
        LoadString(hInstance, ID_TAB_PROCESS + iPage, achTemp, sizeof(achTemp) / sizeof(achTemp[0]));
        SendMessage(hWndCommItems, WM_SETTEXT, NULL, (LPARAM)achTemp);
        break;
    }

    return TRUE;
}

HWND CreateCommItemsTabControl(HWND hWndTab, HINSTANCE hInstance)
{
    RECT rc{};
    GetClientRect(hWndTab, &rc);

    auto hWndCommItems = CreateWindow(WC_STATIC, _TEXT(""), WS_CHILD | WS_VISIBLE, NULL, 25, 100, 100, hWndTab, nullptr, hInstance, nullptr);

    return hWndCommItems;
}

VOID SetView(HWND hWndListView, DWORD dwView)
{
    DWORD dwStyle = GetWindowLong(hWndListView, GWL_STYLE);

    if ((dwStyle & LVS_TYPEMASK) != dwView) {
        SetWindowLong(hWndListView, GWL_STYLE, (dwStyle & ~LVS_TYPEMASK) | dwView);
    }
}

BOOL InitListViewColumns(HWND hWndListView, HINSTANCE hInstance)
{
    TCHAR szText[256]{};

    LVCOLUMN lvc{};
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    for (int iCol = 0; iCol < 10; iCol++)
    {
        lvc.iSubItem = iCol;
        lvc.pszText = szText;
        lvc.cx = 100;

        if (iCol < 2) lvc.fmt = LVCFMT_LEFT;
        else lvc.fmt = LVCFMT_RIGHT;

        LoadString(hInstance, LVM_FIRST /*IDS_FIRSTCOLUMN*/ + iCol, szText, sizeof(szText) / sizeof(szText[0]));

        if (ListView_InsertColumn(hWndListView, iCol, &lvc) == -1) return FALSE;
    }

    return TRUE;
}