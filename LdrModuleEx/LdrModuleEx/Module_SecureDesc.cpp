#include "Def.h"


LPCTSTR GetAccessEx(PACTRL_AUDIT ppAuditList, PACTRL_ACCESS ppAccessList)
{
	LPCTSTR Access = nullptr;
	if (ppAuditList) {
		switch (ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Access) {
		case ACTRL_PERM_5:
			Access = _TEXT("ACTRL_KERNEL_VM_WRITE |\n"
				"                                                  ACTRL_DS_READ_PROP |\n"
				"                                                  ACTRL_FILE_WRITE_PROP |\n"
				"                                                  ACTRL_PRINT_JADMIN |\n"
				"                                                  ACTRL_SVC_START |\n"
				"                                                  ACTRL_REG_NOTIFY |\n"
				"                                                  ACTRL_WIN_LIST");
			break;
		default: break;
		}
	}
	if (ppAccessList) {
		switch (ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Access) {
		case ACTRL_RESERVED:
			Access = _TEXT("ACTRL_RESERVED | ACTRL_DS_OPEN");
			break;
		case ACTRL_PERM_1:
			Access = _TEXT("ACTRL_KERNEL_TERMINATE |\n"
				"                                                  ACTRL_DS_CREATE_CHILD |\n"
				"                                                  ACTRL_FILE_READ |\n"
				"                                                  ACTRL_PRINT_SADMIN |\n"
				"                                                  ACTRL_SVC_GET_INFO |\n"
				"                                                  ACTRL_REG_QUERY |\n"
				"                                                  ACTRL_WIN_CLIPBRD |\n"
				"                                                  ACTRL_DIR_LIST");
			break;
		case ACTRL_PERM_2:
			Access = _TEXT("ACTRL_KERNEL_THREAD |\n"
				"                                                  ACTRL_DS_DELETE_CHILD |\n"
				"                                                  ACTRL_FILE_WRITE |\n"
				"                                                  ACTRL_PRINT_SLIST |\n"
				"                                                  ACTRL_SVC_SET_INFO |\n"
				"                                                  ACTRL_REG_SET |\n"
				"                                                  ACTRL_WIN_GLOBAL_ATOMS |\n"
				"                                                  ACTRL_DIR_CREATE_OBJECT");
			break;
		case ACTRL_PERM_3:
			Access = _TEXT("ACTRL_KERNEL_VM |\n"
				"                                                  ACTRL_DS_LIST |\n"
				"                                                  ACTRL_FILE_APPEND |\n"
				"                                                  ACTRL_PRINT_PADMIN |\n"
				"                                                  ACTRL_SVC_STATUS |\n"
				"                                                  ACTRL_REG_CREATE_CHILD |\n"
				"                                                  ACTRL_WIN_CREATE |\n"
				"                                                  ACTRL_DIR_CREATE_CHILD");
			break;
		case ACTRL_PERM_4:
			Access = _TEXT("ACTRL_KERNEL_VM_READ |\n"
				"                                                  ACTRL_DS_SELF |\n"
				"                                                  ACTRL_FILE_READ_PROP |\n"
				"                                                  ACTRL_PRINT_PUSE |\n"
				"                                                  ACTRL_SVC_LIST |\n"
				"                                                  ACTRL_REG_LIST |\n"
				"                                                  ACTRL_WIN_LIST_DESK");
			break;
		case ACTRL_PERM_5:
			Access = _TEXT("ACTRL_KERNEL_VM_WRITE |\n"
				"                                                  ACTRL_DS_READ_PROP |\n"
				"                                                  ACTRL_FILE_WRITE_PROP |\n"
				"                                                  ACTRL_PRINT_JADMIN |\n"
				"                                                  ACTRL_SVC_START |\n"
				"                                                  ACTRL_REG_NOTIFY |\n"
				"                                                  ACTRL_WIN_LIST");
			break;
		case ACTRL_PERM_6:
			Access = _TEXT("ACTRL_KERNEL_DUP_HANDLE |\n"
				"                                                  ACTRL_DS_WRITE_PROP |\n"
				"                                                  ACTRL_FILE_EXECUTE |\n"
				"                                                  ACTRL_DIR_TRAVERSE |\n"
				"                                                  ACTRL_SVC_STOP |\n"
				"                                                  ACTRL_REG_LINK |\n"
				"                                                  ACTRL_WIN_READ_ATTRIBS");
			break;
		case ACTRL_PERM_7:
			Access = _TEXT("ACTRL_KERNEL_PROCESS |\n"
				"                                                  ACTRL_DS_DELETE_TREE |\n"
				"                                                  ACTRL_SVC_PAUSE |\n"
				"                                                  ACTRL_WIN_WRITE_ATTRIBS |\n"
				"                                                  ACTRL_DIR_DELETE_CHILD");
			break;
		case ACTRL_PERM_8:
			Access = _TEXT("ACTRL_KERNEL_SET_INFO |\n"
				"                                                  ACTRL_DS_LIST_OBJECT |\n"
				"                                                  ACTRL_FILE_READ_ATTRIB |\n"
				"                                                  ACTRL_SVC_INTERROGATE |\n"
				"                                                  ACTRL_WIN_SCREEN");
			break;
		case ACTRL_PERM_9:
			Access = _TEXT("ACTRL_KERNEL_GET_INFO |\n"
				"                                                  ACTRL_DS_CONTROL_ACCESS |\n"
				"                                                  ACTRL_FILE_WRITE_ATTRIB |\n"
				"                                                  ACTRL_SVC_UCONTROL |\n"
				"                                                  ACTRL_WIN_EXIT");
			break;
		case ACTRL_PERM_10:
			Access = _TEXT("ACTRL_KERNEL_CONTROL | ACTRL_FILE_CREATE_PIPE");
			break;
		case ACTRL_PERM_11:
			Access = _TEXT("ACTRL_KERNEL_ALERT");
			break;
		case ACTRL_PERM_12:
			Access = _TEXT("ACTRL_KERNEL_GET_CONTEXT");
			break;
		case ACTRL_PERM_13:
			Access = _TEXT("ACTRL_KERNEL_SET_CONTEXT");
			break;
		case ACTRL_PERM_14:
			Access = _TEXT("ACTRL_KERNEL_TOKEN");
			break;
		case ACTRL_PERM_15:
			Access = _TEXT("ACTRL_KERNEL_IMPERSONATE");
			break;
		case ACTRL_PERM_16:
			Access = _TEXT("ACTRL_KERNEL_DIMPERSONATE");
			break;
		case ACTRL_PERM_17:
			Access = _TEXT("ACTRL_PERM_17");
			break;
		case ACTRL_PERM_18:
			Access = _TEXT("ACTRL_PERM_18");
			break;
		case ACTRL_PERM_19:
			Access = _TEXT("ACTRL_PERM_19");
			break;
		case ACTRL_PERM_20:
			Access = _TEXT("ACTRL_PERM_20");
			break;
		case ACTRL_STD_RIGHTS_ALL | ACTRL_PERM_2 | ACTRL_PERM_1:
			Access = _TEXT("ACTRL_STD_RIGHTS_ALL |\n"
				"                                                  ACTRL_KERNEL_THREAD | ACTRL_KERNEL_TERMINATE |\n"
				"                                                  ACTRL_DS_DELETE_CHILD | ACTRL_DS_CREATE_CHILD |\n"
				"                                                  ACTRL_FILE_WRITE | ACTRL_FILE_READ |\n"
				"                                                  ACTRL_PRINT_SLIST | ACTRL_PRINT_SADMIN |\n"
				"                                                  ACTRL_SVC_SET_INFO | ACTRL_SVC_GET_INFO |\n"
				"                                                  ACTRL_REG_SET | ACTRL_REG_QUERY |\n"
				"                                                  ACTRL_WIN_GLOBAL_ATOMS | ACTRL_WIN_CLIPBRD |\n"
				"                                                  ACTRL_DIR_CREATE_OBJECT | ACTRL_DIR_LIST");
			break;
		case ACTRL_STD_RIGHTS_ALL | ACTRL_PERM_7 | ACTRL_PERM_2 | ACTRL_PERM_1:
			Access = _TEXT("ACTRL_STD_RIGHTS_ALL |\n"
				"                                                  ACTRL_KERNEL_PROCESS | ACTRL_KERNEL_THREAD | ACTRL_KERNEL_TERMINATE |\n"
				"                                                  ACTRL_DS_DELETE_TREE | ACTRL_DS_DELETE_CHILD | ACTRL_DS_CREATE_CHILD |\n"
				"                                                  ACTRL_FILE_WRITE | ACTRL_FILE_READ |\n"
				"                                                  ACTRL_PRINT_SLIST | ACTRL_PRINT_SADMIN |\n"
				"                                                  ACTRL_SVC_PAUSE | ACTRL_SVC_SET_INFO | ACTRL_SVC_GET_INFO |\n"
				"                                                  ACTRL_REG_SET | ACTRL_REG_QUERY |\n"
				"                                                  ACTRL_WIN_WRITE_ATTRIBS | ACTRL_WIN_GLOBAL_ATOMS | ACTRL_WIN_CLIPBRD |\n"
				"                                                  ACTRL_DIR_DELETE_CHILD | ACTRL_DIR_CREATE_OBJECT | ACTRL_DIR_LIST");
			break;
		case ACTRL_PERM_13 | ACTRL_PERM_11:
			Access = _TEXT("ACTRL_KERNEL_ALERT | ACTRL_KERNEL_SET_CONTEXT");
			break;
		case ACTRL_READ_CONTROL:
			Access = _TEXT("ACTRL_READ_CONTROL");
			break;
		case ACTRL_READ_CONTROL | ACTRL_PERM_5 | ACTRL_PERM_4:
			Access = _TEXT("ACTRL_READ_CONTROL |\n"
				"                                                  ACTRL_KERNEL_VM_WRITE | ACTRL_KERNEL_VM_READ |\n"
				"                                                  ACTRL_DS_READ_PROP | ACTRL_DS_SELF |\n"
				"                                                  ACTRL_FILE_WRITE_PROP | ACTRL_FILE_READ_PROP |\n"
				"                                                  ACTRL_PRINT_JADMIN | ACTRL_PRINT_PUSE |\n"
				"                                                  ACTRL_SVC_START | ACTRL_SVC_LIST |\n"
				"                                                  ACTRL_REG_NOTIFY | ACTRL_REG_LIST |\n"
				"                                                  ACTRL_WIN_LIST | ACTRL_WIN_LIST_DESK");
			break;
		case ACTRL_READ_CONTROL | ACTRL_PERM_12 | ACTRL_PERM_11 | ACTRL_PERM_7 | ACTRL_PERM_6 | ACTRL_PERM_5 | ACTRL_PERM_4 | ACTRL_PERM_1:
			Access = _TEXT("ACTRL_READ_CONTROL |\n"
				"                                                  ACTRL_KERNEL_GET_CONTEXT | ACTRL_KERNEL_ALERT | ACTRL_KERNEL_PROCESS | ACTRL_KERNEL_DUP_HANDLE | ACTRL_KERNEL_VM_WRITE | ACTRL_KERNEL_VM_READ | ACTRL_KERNEL_TERMINATE |\n"
				"                                                  ACTRL_DS_DELETE_TREE | ACTRL_DS_WRITE_PROP | ACTRL_DS_READ_PROP | ACTRL_DS_SELF | ACTRL_DS_CREATE_CHILD |\n"
				"                                                  ACTRL_FILE_EXECUTE | ACTRL_FILE_WRITE_PROP | ACTRL_FILE_READ_PROP | ACTRL_FILE_READ |\n"
				"                                                  ACTRL_PRINT_JADMIN | ACTRL_PRINT_SADMIN | ACTRL_PRINT_PUSE |\n"
				"                                                  ACTRL_SVC_PAUSE | ACTRL_SVC_STOP | ACTRL_SVC_START | ACTRL_SVC_LIST | ACTRL_SVC_GET_INFO |\n"
				"                                                  ACTRL_REG_LINK | ACTRL_REG_NOTIFY | ACTRL_REG_LIST | ACTRL_REG_QUERY |\n"
				"                                                  ACTRL_WIN_WRITE_ATTRIBS | ACTRL_WIN_READ_ATTRIBS | ACTRL_WIN_LIST | ACTRL_WIN_LIST_DESK | ACTRL_WIN_CLIPBRD |\n"
				"                                                  ACTRL_DIR_DELETE_CHILD | ACTRL_DIR_TRAVERSE | ACTRL_DIR_LIST");
			break;
		case ACTRL_SYNCHRONIZE:
			Access = _TEXT("ACTRL_SYNCHRONIZE");
			break;
		case ACTRL_SYNCHRONIZE | ACTRL_PERM_1:
			Access = _TEXT("ACTRL_SYNCHRONIZE |\n"
				"                                                  ACTRL_KERNEL_TERMINATE |\n"
				"                                                  ACTRL_DS_CREATE_CHILD |\n"
				"                                                  ACTRL_FILE_READ |\n"
				"                                                  ACTRL_PRINT_SADMIN |\n"
				"                                                  ACTRL_SVC_GET_INFO |\n"
				"                                                  ACTRL_REG_QUERY |\n"
				"                                                  ACTRL_WIN_CLIPBRD |\n"
				"                                                  ACTRL_DIR_LIST");
			break;
		case ACTRL_STD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL:
			Access = _TEXT("ACTRL_STD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL");
			break;
		case ACTRL_SYNCHRONIZE | ACTRL_READ_CONTROL | ACTRL_PERM_12 | ACTRL_PERM_7 | ACTRL_PERM_4:
			Access = _TEXT("ACTRL_SYNCHRONIZE | ACTRL_READ_CONTROL |\n"
				"                                                  ACTRL_KERNEL_GET_CONTEXT | ACTRL_KERNEL_PROCESS | ACTRL_KERNEL_VM_READ |\n"
				"                                                  ACTRL_DS_DELETE_TREE | ACTRL_DS_SELF |\n"
				"                                                  ACTRL_FILE_READ_PROP |\n"
				"                                                  ACTRL_PRINT_PUSE |\n"
				"                                                  ACTRL_SVC_PAUSE | ACTRL_SVC_LIST |\n"
				"                                                  ACTRL_REG_LIST |\n"
				"                                                  ACTRL_WIN_WRITE_ATTRIBS | ACTRL_WIN_LIST_DESK |\n"
				"                                                  ACTRL_DIR_DELETE_CHILD");
			break;
			break;
		case ACTRL_SYNCHRONIZE | ACTRL_READ_CONTROL | ACTRL_PERM_13 | ACTRL_PERM_12 | ACTRL_PERM_7 | ACTRL_PERM_4:
			Access = _TEXT("ACTRL_SYNCHRONIZE | ACTRL_READ_CONTROL |\n"
				"                                                  ACTRL_KERNEL_SET_CONTEXT | ACTRL_KERNEL_GET_CONTEXT | ACTRL_KERNEL_PROCESS | ACTRL_KERNEL_VM_READ |\n"
				"                                                  ACTRL_DS_DELETE_TREE | ACTRL_DS_SELF |\n"
				"                                                  ACTRL_FILE_READ_PROP |\n"
				"                                                  ACTRL_PRINT_PUSE |\n"
				"                                                  ACTRL_SVC_PAUSE | ACTRL_SVC_LIST |\n"
				"                                                  ACTRL_REG_LIST |\n"
				"                                                  ACTRL_WIN_WRITE_ATTRIBS | ACTRL_WIN_LIST_DESK |\n"
				"                                                  ACTRL_DIR_DELETE_CHILD");
			break;
		case ACTRL_SYNCHRONIZE | ACTRL_READ_CONTROL | ACTRL_PERM_13 | ACTRL_PERM_11 | ACTRL_PERM_5 | ACTRL_PERM_1:
			Access = _TEXT("ACTRL_SYNCHRONIZE | ACTRL_READ_CONTROL |\n"
				"                                                  ACTRL_KERNEL_SET_CONTEXT | ACTRL_KERNEL_ALERT | ACTRL_KERNEL_VM_WRITE | ACTRL_KERNEL_TERMINATE |\n"
				"                                                  ACTRL_DS_READ_PROP | ACTRL_DS_CREATE_CHILD |\n"
				"                                                  ACTRL_FILE_WRITE_PROP | ACTRL_FILE_READ |\n"
				"                                                  ACTRL_PRINT_JADMIN | ACTRL_PRINT_SADMIN |\n"
				"                                                  ACTRL_SVC_START | ACTRL_SVC_GET_INFO |\n"
				"                                                  ACTRL_REG_NOTIFY | ACTRL_REG_QUERY |\n"
				"                                                  ACTRL_WIN_LIST | ACTRL_WIN_CLIPBRD |\n"
				"                                                  ACTRL_DIR_LIST");
			break;
		default: break;
		}
	}
	return Access;
}

LPCTSTR GetAccessFlagEx(PACTRL_AUDIT ppAuditList, PACTRL_ACCESS ppAccessList)
{
	LPCTSTR AccessFlag = nullptr;
	if (ppAuditList) {
		switch (ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->fAccessFlags) {
		case ACTRL_ACCESS_ALLOWED: AccessFlag = _TEXT("ACTRL_ACCESS_ALLOWED"); break;
		case ACTRL_ACCESS_DENIED: AccessFlag = _TEXT("ACTRL_ACCESS_DENIED"); break;
		case ACTRL_AUDIT_SUCCESS: AccessFlag = _TEXT("ACTRL_AUDIT_SUCCESS"); break;
		case ACTRL_AUDIT_FAILURE: AccessFlag = _TEXT("ACTRL_AUDIT_FAILURE"); break;
		case ACTRL_AUDIT_SUCCESS | ACTRL_AUDIT_FAILURE: AccessFlag = _TEXT("ACTRL_AUDIT_SUCCESS | ACTRL_AUDIT_FAILURE"); break;
		default: break;
		}
	}
	if (ppAccessList) {
		switch (ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->fAccessFlags) {
		case ACTRL_ACCESS_ALLOWED: AccessFlag = _TEXT("ACTRL_ACCESS_ALLOWED"); break;
		case ACTRL_ACCESS_DENIED: AccessFlag = _TEXT("ACTRL_ACCESS_DENIED"); break;
		case ACTRL_AUDIT_SUCCESS: AccessFlag = _TEXT("ACTRL_AUDIT_SUCCESS"); break;
		case ACTRL_AUDIT_FAILURE: AccessFlag = _TEXT("ACTRL_AUDIT_FAILURE"); break;
		default: break;
		}
	}
	return AccessFlag;
}

LPCTSTR GetInheritanceEx(PACTRL_AUDIT ppAuditList, PACTRL_ACCESS ppAccessList)
{
	LPCTSTR Inheritance = nullptr;
	if (ppAuditList) {
		switch (ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Inheritance) {
		case NO_INHERITANCE: Inheritance = _TEXT("NO_INHERITANCE"); break;
		case SUB_OBJECTS_ONLY_INHERIT: Inheritance = _TEXT("SUB_OBJECTS_ONLY_INHERIT"); break;
		case SUB_CONTAINERS_ONLY_INHERIT: Inheritance = _TEXT("SUB_CONTAINERS_ONLY_INHERIT"); break;
		case SUB_CONTAINERS_AND_OBJECTS_INHERIT: Inheritance = _TEXT("SUB_CONTAINERS_AND_OBJECTS_INHERIT"); break;
		case INHERIT_NO_PROPAGATE: Inheritance = _TEXT("INHERIT_NO_PROPAGATE"); break;
		case INHERIT_ONLY: Inheritance = _TEXT("INHERIT_ONLY"); break;
		default: break;
		}
	}
	if (ppAccessList) {
		switch (ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Inheritance) {
		case NO_INHERITANCE: Inheritance = _TEXT("NO_INHERITANCE"); break;
		case SUB_OBJECTS_ONLY_INHERIT: Inheritance = _TEXT("SUB_OBJECTS_ONLY_INHERIT"); break;
		case SUB_CONTAINERS_ONLY_INHERIT: Inheritance = _TEXT("SUB_CONTAINERS_ONLY_INHERIT"); break;
		case SUB_CONTAINERS_AND_OBJECTS_INHERIT: Inheritance = _TEXT("SUB_CONTAINERS_AND_OBJECTS_INHERIT"); break;
		case INHERIT_NO_PROPAGATE: Inheritance = _TEXT("INHERIT_NO_PROPAGATE"); break;
		case INHERIT_ONLY: Inheritance = _TEXT("INHERIT_ONLY"); break;
		default: break;
		}
	}
	return Inheritance;
}

LPCTSTR GetMultipleTrusteeEx(PACTRL_AUDIT ppAuditList, PACTRL_ACCESS ppAccessList)
{
	LPCTSTR MultipleTrustee = nullptr;
	if (ppAuditList) {
		switch (ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.MultipleTrusteeOperation) {
		case 0: MultipleTrustee = _TEXT("NULL"); break;
		default: break;
		}
	}
	if (ppAccessList) {
		switch (ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.MultipleTrusteeOperation) {
		case 0: MultipleTrustee = _TEXT("NULL"); break;
		default: break;
		}
	}
	return MultipleTrustee;
}

LPCTSTR GetMultipleTrusteeOperationEx(PACTRL_AUDIT ppAuditList, PACTRL_ACCESS ppAccessList)
{
	LPCTSTR MultipleTrusteeOperation = nullptr;
	if (ppAuditList) {
		switch (ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.MultipleTrusteeOperation) {
		case NO_MULTIPLE_TRUSTEE: MultipleTrusteeOperation = _TEXT("NO_MULTIPLE_TRUSTEE"); break;
		case TRUSTEE_IS_IMPERSONATE: MultipleTrusteeOperation = _TEXT("TRUSTEE_IS_IMPERSONATE"); break;
		default: break;
		}
	}
	if (ppAccessList) {
		switch (ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.MultipleTrusteeOperation) {
		case NO_MULTIPLE_TRUSTEE: MultipleTrusteeOperation = _TEXT("NO_MULTIPLE_TRUSTEE"); break;
		case TRUSTEE_IS_IMPERSONATE: MultipleTrusteeOperation = _TEXT("TRUSTEE_IS_IMPERSONATE"); break;
		default: break;
		}
	}
	return MultipleTrusteeOperation;
}

LPCTSTR GetTrusteeFormEx(PACTRL_AUDIT ppAuditList, PACTRL_ACCESS ppAccessList)
{
	LPCTSTR TrusteeForm = nullptr;
	if (ppAuditList) {
		switch (ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.TrusteeForm) {
		case TRUSTEE_IS_SID: TrusteeForm = _TEXT("TRUSTEE_IS_SID"); break;
		case TRUSTEE_IS_NAME: TrusteeForm = _TEXT("TRUSTEE_IS_NAME"); break;
		case TRUSTEE_BAD_FORM: TrusteeForm = _TEXT("TRUSTEE_BAD_FORM"); break;
		case TRUSTEE_IS_OBJECTS_AND_SID: TrusteeForm = _TEXT("TRUSTEE_IS_OBJECTS_AND_SID"); break;
		case TRUSTEE_IS_OBJECTS_AND_NAME: TrusteeForm = _TEXT("TRUSTEE_IS_OBJECTS_AND_NAME"); break;
		default: break;
		}
	}
	if (ppAccessList) {
		switch (ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.TrusteeForm) {
		case TRUSTEE_IS_SID: TrusteeForm = _TEXT("TRUSTEE_IS_SID"); break;
		case TRUSTEE_IS_NAME: TrusteeForm = _TEXT("TRUSTEE_IS_NAME"); break;
		case TRUSTEE_BAD_FORM: TrusteeForm = _TEXT("TRUSTEE_BAD_FORM"); break;
		case TRUSTEE_IS_OBJECTS_AND_SID: TrusteeForm = _TEXT("TRUSTEE_IS_OBJECTS_AND_SID"); break;
		case TRUSTEE_IS_OBJECTS_AND_NAME: TrusteeForm = _TEXT("TRUSTEE_IS_OBJECTS_AND_NAME"); break;
		default: break;
		}
	}
	return TrusteeForm;
}

LPCTSTR GetTrusteeTypeEx(PACTRL_AUDIT ppAuditList, PACTRL_ACCESS ppAccessList)
{
	LPCTSTR TrusteeType = nullptr;
	if (ppAuditList) {
		switch (ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.TrusteeType) {
		case TRUSTEE_IS_UNKNOWN: TrusteeType = _TEXT("TRUSTEE_IS_UNKNOWN"); break;
		case TRUSTEE_IS_USER: TrusteeType = _TEXT("TRUSTEE_IS_USER"); break;
		case TRUSTEE_IS_GROUP: TrusteeType = _TEXT("TRUSTEE_IS_GROUP"); break;
		case TRUSTEE_IS_DOMAIN: TrusteeType = _TEXT("TRUSTEE_IS_DOMAIN"); break;
		case TRUSTEE_IS_ALIAS: TrusteeType = _TEXT("TRUSTEE_IS_ALIAS"); break;
		case TRUSTEE_IS_WELL_KNOWN_GROUP: TrusteeType = _TEXT("TRUSTEE_IS_WELL_KNOWN_GROUP"); break;
		case TRUSTEE_IS_DELETED: TrusteeType = _TEXT("TRUSTEE_IS_DELETED"); break;
		case TRUSTEE_IS_INVALID: TrusteeType = _TEXT("TRUSTEE_IS_INVALID"); break;
		case TRUSTEE_IS_COMPUTER: TrusteeType = _TEXT("TRUSTEE_IS_COMPUTER"); break;
		case 9: TrusteeType = _TEXT("TRUSTEE_IS::9"); break;
		case 10: TrusteeType = _TEXT("TRUSTEE_IS::10"); break;
		case 11: TrusteeType = _TEXT("TRUSTEE_IS_LOGON"); break;
		default: break;
		}
	}
	if (ppAccessList) {
		switch (ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.TrusteeType) {
		case TRUSTEE_IS_UNKNOWN: TrusteeType = _TEXT("TRUSTEE_IS_UNKNOWN"); break;
		case TRUSTEE_IS_USER: TrusteeType = _TEXT("TRUSTEE_IS_USER"); break;
		case TRUSTEE_IS_GROUP: TrusteeType = _TEXT("TRUSTEE_IS_GROUP"); break;
		case TRUSTEE_IS_DOMAIN: TrusteeType = _TEXT("TRUSTEE_IS_DOMAIN"); break;
		case TRUSTEE_IS_ALIAS: TrusteeType = _TEXT("TRUSTEE_IS_ALIAS"); break;
		case TRUSTEE_IS_WELL_KNOWN_GROUP: TrusteeType = _TEXT("TRUSTEE_IS_WELL_KNOWN_GROUP"); break;
		case TRUSTEE_IS_DELETED: TrusteeType = _TEXT("TRUSTEE_IS_DELETED"); break;
		case TRUSTEE_IS_INVALID: TrusteeType = _TEXT("TRUSTEE_IS_INVALID"); break;
		case TRUSTEE_IS_COMPUTER: TrusteeType = _TEXT("TRUSTEE_IS_COMPUTER"); break;
		case 9: TrusteeType = _TEXT("TRUSTEE_IS::9"); break;
		case 10: TrusteeType = _TEXT("TRUSTEE_IS::10"); break;
		case 11: TrusteeType = _TEXT("TRUSTEE_IS_LOGON"); break;
		default: break;
		}
	}
	return TrusteeType;
}

LPCTSTR GetDaclMask(LPVOID DaclAceAddress)
{
	LPCTSTR DaclMask = nullptr;
	switch (((PACCESS_ALLOWED_ACE)DaclAceAddress)->Mask) {
	case STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL: DaclMask = _TEXT("STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL"); break;
	default: break;
	}

	return DaclMask;
}

VOID ACTRLPrint(PACTRL_AUDIT ppAuditList, PACTRL_ACCESS ppAccessList)
{
	_tout << _TEXT("\n\n    ACTRL_ALIST:\n    {") << std::endl;

	if (ppAuditList) {
		Sys_SetTextColor(BLUE);
		_tout << _TEXT("        ACTRL_AUDIT->Entries: ") << ppAuditList->cEntries << std::endl;
		if (ppAuditList->cEntries == 0)
			_tout << _TEXT("        ACTRL_AUDIT->PropertyAccessList: 0x") << ppAuditList->pPropertyAccessList << std::endl;
		for (unsigned i = 0; i < ppAuditList->cEntries; i++) {
			_tout <<
				_TEXT("        ACTRL_AUDIT[") << i << _TEXT("].PropertyAccessList: 0x") << ppAuditList->pPropertyAccessList << std::endl <<
				_TEXT("            ACTRL_PROPERTY_ENTRY[") << i << _TEXT("].ListFlags: ") << ppAuditList->pPropertyAccessList->fListFlags << std::endl <<
				_TEXT("            ACTRL_PROPERTY_ENTRY[") << i << _TEXT("].Property: ") << (PWORD)(ppAuditList->pPropertyAccessList->lpProperty) << std::endl <<
				_TEXT("            ACTRL_PROPERTY_ENTRY[") << i << _TEXT("].AccessEntryList: 0x") << ppAuditList->pPropertyAccessList->pAccessEntryList << std::endl;
			_tout << _TEXT("                ACTRL_ACCESS_ENTRY_LIST->Entries: ") << ppAuditList->pPropertyAccessList->pAccessEntryList->cEntries << std::endl;
			if (ppAuditList->pPropertyAccessList->pAccessEntryList->cEntries == 0)
				_tout << _TEXT("                ACTRL_ACCESS_ENTRY_LIST->AccessList: 0x") << ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList << std::endl;
			for (unsigned j = 0; j < ppAuditList->pPropertyAccessList->pAccessEntryList->cEntries; j++) {
				_tout <<
					_TEXT("                ACTRL_ACCESS_ENTRY_LIST[") << j << _TEXT("].AccessList: 0x") << ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList << std::endl <<
					//_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].Access: ") << ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Access << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].Access: ") << GetAccessEx(ppAuditList, nullptr) << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].AccessFlags: ") << GetAccessFlagEx(ppAuditList, nullptr) << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].Inheritance: ") << GetInheritanceEx(ppAuditList, nullptr) << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].InheritProperty: ") << (PWORD)(ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->lpInheritProperty) << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].ProvSpecificAccess: ") << ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->ProvSpecificAccess << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].Trustee: 0x") << &ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].MultipleTrustee: ") << GetMultipleTrusteeEx(ppAuditList, nullptr) << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].MultipleTrusteeOperation: ") << GetMultipleTrusteeOperationEx(ppAuditList, nullptr) << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].Name: ") << ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.ptstrName << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].TrusteeForm: ") << GetTrusteeFormEx(ppAuditList, nullptr) << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].TrusteeType: ") << GetTrusteeTypeEx(ppAuditList, nullptr) << std::endl;
				ppAuditList->pPropertyAccessList->pAccessEntryList->pAccessList++;
			}
			ppAuditList->pPropertyAccessList->pAccessEntryList++;
			ppAuditList->pPropertyAccessList++;
		}
		Sys_SetTextColor(FLUSH);
	}

	if (ppAccessList) {
		Sys_SetTextColor(BLUE_INTENSITY);
		_tout << _TEXT("        ACTRL_ACCESS->Entries: ") << ppAccessList->cEntries << std::endl;
		if (ppAccessList->cEntries == 0)
			_tout << _TEXT("        ACTRL_ACCESS->PropertyAccessList: 0x") << ppAccessList->pPropertyAccessList << std::endl;
		for (unsigned i = 0; i < ppAccessList->cEntries; i++) {
			_tout <<
				_TEXT("        ACTRL_ACCESS[") << i << _TEXT("].PropertyAccessList: 0x") << ppAccessList->pPropertyAccessList << std::endl <<
				_TEXT("            ACTRL_PROPERTY_ENTRY[") << i << _TEXT("].ListFlags: ") << ppAccessList->pPropertyAccessList->fListFlags << std::endl <<
				_TEXT("            ACTRL_PROPERTY_ENTRY[") << i << _TEXT("].Property: ") << (PWORD)(ppAccessList->pPropertyAccessList->lpProperty) << std::endl <<
				_TEXT("            ACTRL_PROPERTY_ENTRY[") << i << _TEXT("].AccessEntryList: 0x") << ppAccessList->pPropertyAccessList->pAccessEntryList << std::endl;
			_tout << _TEXT("                ACTRL_ACCESS_ENTRY_LIST->Entries: ") << ppAccessList->pPropertyAccessList->pAccessEntryList->cEntries << std::endl;
			if (ppAccessList->pPropertyAccessList->pAccessEntryList->cEntries == 0)
				_tout << _TEXT("                ACTRL_ACCESS_ENTRY_LIST->AccessList: 0x") << ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList << std::endl;
			for (unsigned j = 0; j < ppAccessList->pPropertyAccessList->pAccessEntryList->cEntries; j++) {
				_tout <<
					_TEXT("                ACTRL_ACCESS_ENTRY_LIST[") << j << _TEXT("].AccessList: 0x") << ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList << std::endl <<
					//_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].Access: 0x") << std::hex << ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Access <<std::dec << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].Access: ") << GetAccessEx(nullptr, ppAccessList) << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].AccessFlags: ") << GetAccessFlagEx(nullptr, ppAccessList) << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].Inheritance: ") << GetInheritanceEx(nullptr, ppAccessList) << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].InheritProperty: ") << (PWORD)(ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->lpInheritProperty) << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].ProvSpecificAccess: ") << ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->ProvSpecificAccess << std::endl <<
					_TEXT("                    ACTRL_ACCESS_ENTRY[") << j << _TEXT("].Trustee: 0x") << &ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].MultipleTrustee: ") << GetMultipleTrusteeEx(nullptr, ppAccessList) << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].MultipleTrusteeOperation: ") << GetMultipleTrusteeOperationEx(nullptr, ppAccessList) << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].Name: ") << ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.ptstrName << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].TrusteeForm: ") << GetTrusteeFormEx(nullptr, ppAccessList) << std::endl <<
					_TEXT("                        TRUSTEE[") << j << _TEXT("].TrusteeType: ") << GetTrusteeTypeEx(nullptr, ppAccessList) << std::endl;
				ppAccessList->pPropertyAccessList->pAccessEntryList->pAccessList++;
			}
			ppAccessList->pPropertyAccessList->pAccessEntryList++;
			ppAccessList->pPropertyAccessList++;
		}
		Sys_SetTextColor(FLUSH);
	}

	_tout << _TEXT("    }\n}") << std::endl;
}

DWORD Sys_GetSecurityDescriptor(_In_opt_ PSID ppSidOwner, _In_opt_ PSID ppSidGroup, _In_opt_ PACL ppDacl, _In_ PACL ppSacl,
	_In_ PSECURITY_DESCRIPTOR ppSecurityDescriptor, _In_ PACTRL_ACCESS ppAccessList, _In_ PACTRL_AUDIT ppAuditList,
	_In_ LPTSTR ppOwner, _In_ LPTSTR ppGroup, _In_opt_ HANDLE hObject)
{
	PSID_IDENTIFIER_AUTHORITY SidOwnerIdentifierAuthority{}, SidGroupIdentifierAuthority{};
	SECURITY_DESCRIPTOR_CONTROL pControl = NULL;
	DWORD SidRevision = NULL, SidOwnerSubAuthorityCount = NULL, SidGroupSubAuthorityCount = NULL, AceSize = NULL,
		ReturnLength = NULL, UIAccess = FALSE;
	LPVOID SaclAceAddress = nullptr, DaclAceAddress = nullptr;
	HANDLE hToken = nullptr, hDuplicateToken = nullptr;
	LPTSTR SID = nullptr;
	LPCTSTR AceType = nullptr, AceFlag = nullptr, SecurityDescriptorControlFlags = nullptr, IntegrityLevelType = nullptr;

	if (ppSecurityDescriptor) {
		if (!IsValidSecurityDescriptor(ppSecurityDescriptor)) {
			ErrPrint(_TEXT("Sys_GetSecurityDescriptor::IsValidSecurityDescriptor"));
			return EXIT_FAILURE;
		}
		_tout << _TEXT("SECURITY_DESCRIPTOR: 0x") << ppSecurityDescriptor << _TEXT(" (length: ") << GetSecurityDescriptorLength(ppSecurityDescriptor) << _TEXT(" bytes)\n{") << std::endl;
	}

	//================================================================================================================================================================

	GetSecurityDescriptorControl(ppSecurityDescriptor, &pControl, &SidRevision);
	Sys_SetTextColor(WHITE);
	_tout <<
		_TEXT("    SID_REVISION: ") << SidRevision << _TEXT(" (field: ") << sizeof(BYTE) << _TEXT(" byte)\n") <<
		_TEXT("    Sbz1: ") << (WORD)(((PISECURITY_DESCRIPTOR)ppSecurityDescriptor)->Sbz1) << _TEXT(" (field: ") << sizeof(BYTE) << _TEXT(" byte)\n");

	if (pControl == (SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT))
		SecurityDescriptorControlFlags = _TEXT("SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT");
	if (pControl == (SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT | SE_DACL_PRESENT))
		SecurityDescriptorControlFlags = _TEXT("SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT | SE_DACL_PRESENT");
	if (pControl == (SE_SELF_RELATIVE | SE_SACL_PRESENT | SE_DACL_PRESENT))
		SecurityDescriptorControlFlags = _TEXT("SE_SELF_RELATIVE | SE_SACL_PRESENT | SE_DACL_PRESENT");

	_tout << _TEXT("    Flags: ") << SecurityDescriptorControlFlags << _TEXT(" (field: ") << sizeof(SECURITY_DESCRIPTOR_CONTROL) << _TEXT(" bytes)\n");

	if (ppSidGroup) {
		if (!IsValidSid(ppSidGroup)) {
			ErrPrint(_TEXT("Sys_GetSecurityDescriptor::IsValidSid::ppSidGroup"));
			return EXIT_FAILURE;
		}
		_tout << _TEXT("    Offset group: 0x") << ppSidGroup << _TEXT(" (field: ") << sizeof(DWORD) << _TEXT(" bytes)\n");
	}
	if (ppSidOwner) {
		if (!IsValidSid(ppSidOwner)) {
			ErrPrint(_TEXT("Sys_GetSecurityDescriptor::IsValidSid::ppSidOwner"));
			return EXIT_FAILURE;
		}
		_tout << _TEXT("    Offset owner: 0x") << ppSidOwner << _TEXT(" (field: ") << sizeof(DWORD) << _TEXT(" bytes)\n");
	}
	if (ppSacl) {
		if (!IsValidAcl(ppSacl)) {
			ErrPrint(_TEXT("Sys_GetSecurityDescriptor::IsValidAcl::ppSacl"));
			return EXIT_FAILURE;
		}
		_tout << _TEXT("    Offset SACL: 0x") << ppSacl << _TEXT(" (field: ") << sizeof(DWORD) << _TEXT(" bytes)\n");
	}
	if (ppDacl) {
		if (!IsValidAcl(ppDacl)) {
			ErrPrint(_TEXT("Sys_GetSecurityDescriptor::IsValidAcl::ppDacl"));
			return EXIT_FAILURE;
		}
		_tout << _TEXT("    Offset DACL: 0x") << ppDacl << _TEXT(" (field: ") << sizeof(DWORD) << _TEXT(" bytes)\n");
	}
	else _tout << _TEXT("    Offset DACL: 0x") << (PACL)((SIZE_T)ppSacl - 0x3C) << _TEXT(" (field: ") << sizeof(DWORD) << _TEXT(" bytes)\n");
	Sys_SetTextColor(FLUSH);

	//================================================================================================================================================================

	if (ppSidGroup) {
		SidGroupIdentifierAuthority = GetSidIdentifierAuthority(ppSidGroup);
		Sys_SetTextColor(MAGENTA);
		_tout << _TEXT("    SID group: ") << _TEXT("S-") << SidRevision << _TEXT("-") << (WORD)SidGroupIdentifierAuthority->Value[5];
		SidGroupSubAuthorityCount = *GetSidSubAuthorityCount(ppSidGroup);
		for (unsigned i = 0; i < SidGroupSubAuthorityCount; ++i) _tout << _TEXT("-") << *GetSidSubAuthority(ppSidGroup, i);
		_tout << _TEXT(" >> ") << ppGroup << _TEXT(" (length: ") << GetLengthSid(ppSidGroup) << _TEXT(" bytes)\n");
		Sys_SetTextColor(FLUSH);
	}
	else {
		Sys_SetTextColor(MAGENTA);
		if (WIN_VISTA || WIN_7) _tout << _TEXT("    SID group: ") << _TEXT("S-") << SidRevision << _TEXT("-5-18 >> NT AUTHORITY\\система");
		else _tout << _TEXT("    SID group: ") << _TEXT("S-") << SidRevision << _TEXT("-5-18 >> NT AUTHORITY\\СИСТЕМА");
		_tout << _TEXT(" (length: ") << GetSecurityDescriptorLength(ppSecurityDescriptor) - sizeof(SECURITY_DESCRIPTOR_CONTROL) * 4 - ppSacl->AclSize << _TEXT(" bytes)\n");
		Sys_SetTextColor(FLUSH);
	}
	if (ppSidOwner) {
		SidOwnerIdentifierAuthority = GetSidIdentifierAuthority(ppSidOwner);
		Sys_SetTextColor(MAGENTA);
		_tout << _TEXT("    SID owner: ") << _TEXT("S-") << SidRevision << _TEXT("-") << (WORD)SidOwnerIdentifierAuthority->Value[5];
		SidOwnerSubAuthorityCount = *GetSidSubAuthorityCount(ppSidOwner);
		for (unsigned i = 0; i < SidOwnerSubAuthorityCount; ++i) _tout << _TEXT("-") << *GetSidSubAuthority(ppSidOwner, i);
		_tout << _TEXT(" >> ") << ppOwner << _TEXT(" (length: ") << GetLengthSid(ppSidOwner) << _TEXT(" bytes)\n");
		Sys_SetTextColor(FLUSH);
	}
	else {
		Sys_SetTextColor(MAGENTA);
		_tout << _TEXT("    SID owner: ") << _TEXT("S-") << SidRevision << _TEXT("-5-32-544 >> BUILTIN\\Администраторы");
		_tout << _TEXT(" (length: ") << GetSecurityDescriptorLength(ppSecurityDescriptor) - sizeof(SECURITY_DESCRIPTOR_CONTROL) * 2 - ppSacl->AclSize << _TEXT(" bytes)\n");
		Sys_SetTextColor(FLUSH);
	}

	//================================================================================================================================================================

	if (!OpenProcessToken(hObject, TOKEN_QUERY, &hToken)) ErrPrint(_TEXT("Sys_GetSecurityDescriptor::OpenProcessToken"));
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, NULL, &ReturnLength)) {
		if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
			auto TokenInfoLength = ReturnLength;
			auto TokenMandatoryLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LMEM_FIXED, TokenInfoLength);
			if (TokenMandatoryLabel != nullptr) {
				if (GetTokenInformation(hToken, TokenIntegrityLevel, TokenMandatoryLabel, TokenInfoLength, &ReturnLength)) {
					auto IntegrityLevel = *GetSidSubAuthority(TokenMandatoryLabel->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(TokenMandatoryLabel->Label.Sid) - 1));
					if(!GetTokenInformation(hToken, TokenUIAccess, &UIAccess, sizeof(DWORD), &ReturnLength)) ErrPrint(_TEXT("Sys_GetSecurityDescriptor::GetTokenInformation"));
					switch (IntegrityLevel) {
					case SECURITY_MANDATORY_UNTRUSTED_RID: IntegrityLevelType = _TEXT("ML_UNTRUSTED"); break;
					case SECURITY_MANDATORY_LOW_RID: IntegrityLevelType = _TEXT("ML_LOW"); break;
					case SECURITY_MANDATORY_MEDIUM_RID:
						IntegrityLevelType = _TEXT("ML_MEDIUM");
						if(UIAccess == TRUE) IntegrityLevelType = _TEXT("ML_MEDIUM_UIACCESS"); break;
					case SECURITY_MANDATORY_MEDIUM_PLUS_RID: IntegrityLevelType = _TEXT("ML_MEDIUM_PLUS"); break;
					case SECURITY_MANDATORY_HIGH_RID:
						IntegrityLevelType = _TEXT("ML_HIGH");
						if (UIAccess == TRUE) IntegrityLevelType = _TEXT("ML_HIGH_UIACCESS"); break;
					case SECURITY_MANDATORY_SYSTEM_RID: IntegrityLevelType = _TEXT("ML_SYSTEM"); break;
					case SECURITY_MANDATORY_PROTECTED_PROCESS_RID: IntegrityLevelType = _TEXT("ML_PROTECTED_PROCESS"); break;
					case SECURITY_MANDATORY_SECURE_PROCESS_RID: IntegrityLevelType = _TEXT("ML_SECURE_PROCESS"); break;
					default: IntegrityLevelType = _TEXT("fuck"); break;
					}
				}
				else ErrPrint(_TEXT("Sys_GetSecurityDescriptor::GetTokenInformation"));
			}
			else ErrPrint(_TEXT("Sys_GetSecurityDescriptor::TokenMandatoryLabel::TOKEN_MANDATORY_LABEL"));
			LocalFree(TokenMandatoryLabel);
		}
	}
	Sys_CloseHandle(hToken);

	//================================================================================================================================================================

	if (ppSacl)
	{
		Sys_SetTextColor(BLUE);
		_tout <<
			_TEXT("    SACL_REVISION: ") << (WORD)ppSacl->AclRevision << std::endl <<
			_TEXT("    SACL Sbz1: ") << (WORD)ppSacl->Sbz1 << std::endl;

		if (ppSacl->AceCount == NULL) {
			_tout <<
				_TEXT("    SACL size: ") << ppSacl->AclSize + (WORD)((SIZE_T)ppSacl - (SIZE_T)ppSecurityDescriptor) << _TEXT(" bytes\n") <<
				_TEXT("    SACL:ACE count: ") << ppSacl->AceCount + 1 << std::endl;
			AceFlag = _TEXT("0");
			AceType = _TEXT("SYSTEM_MANDATORY_LABEL_ACE_TYPE");
			SID = (LPTSTR)_TEXT("S-1-16-20480");
			IntegrityLevelType = _TEXT("ML_PROTECTED_PROCESS");
			_tout <<
				_TEXT("        SACL:ACE[0].address: 0x") << (PACL)((SIZE_T)ppSacl + sizeof(SIZE_T)) << std::endl <<
				_TEXT("            SACL:ACE[0].AceType: ") << AceType << std::endl <<
				_TEXT("            SACL:ACE[0].AceFlag: ") << AceFlag << std::endl <<
				_TEXT("            SACL:ACE[0].AceSize: ") << (WORD)((SIZE_T)ppSacl - (SIZE_T)ppSecurityDescriptor) << _TEXT(" bytes\n") <<
				_TEXT("            SACL:ACE[0].Mask: 0x3") << std::endl <<
				_TEXT("            SACL:ACE[0]->SID: ") << SID << std::endl <<
				_TEXT("            SACL:ACE[0]->RID: ") << IntegrityLevelType << std::endl;
		}
		else {
			_tout <<
				_TEXT("    SACL size: ") << ppSacl->AclSize << _TEXT(" bytes\n") <<
				_TEXT("    SACL:ACE count: ") << ppSacl->AceCount << std::endl;
		}

		for (unsigned i = 0; i < ppSacl->AceCount; i++) {
			GetAce(ppSacl, i, &SaclAceAddress);
			if ((WORD)(((PSYSTEM_AUDIT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_AUDIT_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_AUDIT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_AUDIT_ACE_TYPE) AceType = _TEXT("SYSTEM_AUDIT_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_AUDIT_ACE)SaclAceAddress)->Header.AceType);
				if ((WORD)(((PSYSTEM_AUDIT_ACE)SaclAceAddress)->Header.AceFlags) == SUCCESSFUL_ACCESS_ACE_FLAG) AceFlag = _TEXT("SUCCESSFUL_ACCESS_ACE_FLAG");
				else if ((WORD)(((PSYSTEM_AUDIT_ACE)SaclAceAddress)->Header.AceFlags) == FAILED_ACCESS_ACE_FLAG) AceFlag = _TEXT("FAILED_ACCESS_ACE_FLAG");
				else if ((WORD)(((PSYSTEM_AUDIT_ACE)SaclAceAddress)->Header.AceFlags) == (SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG)) AceFlag = _TEXT("SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG");
				else AceFlag = (LPCTSTR)(WORD)(((PSYSTEM_AUDIT_ACE)SaclAceAddress)->Header.AceFlags);
				ConvertSidToStringSid(&((PSYSTEM_AUDIT_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << AceFlag << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_AUDIT_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_AUDIT_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_ALARM_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ALARM_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_ALARM_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ALARM_ACE_TYPE) AceType = _TEXT("SYSTEM_ALARM_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_ALARM_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_ALARM_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_ALARM_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_ALARM_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_ALARM_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_AUDIT_OBJECT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_AUDIT_OBJECT_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_AUDIT_OBJECT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_AUDIT_OBJECT_ACE_TYPE) AceType = _TEXT("SYSTEM_AUDIT_OBJECT_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_AUDIT_OBJECT_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_AUDIT_OBJECT_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_AUDIT_OBJECT_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_AUDIT_OBJECT_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_AUDIT_OBJECT_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_ALARM_OBJECT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ALARM_OBJECT_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_ALARM_OBJECT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ALARM_OBJECT_ACE_TYPE) AceType = _TEXT("SYSTEM_ALARM_OBJECT_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_ALARM_OBJECT_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_ALARM_OBJECT_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_ALARM_OBJECT_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_ALARM_OBJECT_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_ALARM_OBJECT_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_AUDIT_CALLBACK_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_AUDIT_CALLBACK_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_AUDIT_CALLBACK_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_AUDIT_CALLBACK_ACE_TYPE) AceType = _TEXT("SYSTEM_AUDIT_CALLBACK_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_AUDIT_CALLBACK_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_AUDIT_CALLBACK_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_AUDIT_CALLBACK_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_AUDIT_CALLBACK_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_AUDIT_CALLBACK_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_ALARM_CALLBACK_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ALARM_CALLBACK_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_ALARM_CALLBACK_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ALARM_CALLBACK_ACE_TYPE) AceType = _TEXT("SYSTEM_ALARM_CALLBACK_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_ALARM_CALLBACK_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_ALARM_CALLBACK_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_ALARM_CALLBACK_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_ALARM_CALLBACK_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_ALARM_CALLBACK_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE) AceType = _TEXT("SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_ALARM_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_ALARM_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE) AceType = _TEXT("SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_ALARM_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_ALARM_CALLBACK_OBJECT_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_ALARM_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_ALARM_CALLBACK_OBJECT_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_ALARM_CALLBACK_OBJECT_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_MANDATORY_LABEL_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_MANDATORY_LABEL_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_MANDATORY_LABEL_ACE_TYPE) AceType = _TEXT("SYSTEM_MANDATORY_LABEL_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_MANDATORY_LABEL_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_MANDATORY_LABEL_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_MANDATORY_LABEL_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_MANDATORY_LABEL_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_MANDATORY_LABEL_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->RID: ") << IntegrityLevelType << std::endl;
			}
			if ((WORD)(((PSYSTEM_RESOURCE_ATTRIBUTE_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_RESOURCE_ATTRIBUTE_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE) AceType = _TEXT("SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_RESOURCE_ATTRIBUTE_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_RESOURCE_ATTRIBUTE_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_RESOURCE_ATTRIBUTE_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_RESOURCE_ATTRIBUTE_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_RESOURCE_ATTRIBUTE_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_SCOPED_POLICY_ID_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_SCOPED_POLICY_ID_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_SCOPED_POLICY_ID_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_SCOPED_POLICY_ID_ACE_TYPE) AceType = _TEXT("SYSTEM_SCOPED_POLICY_ID_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_SCOPED_POLICY_ID_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_SCOPED_POLICY_ID_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_SCOPED_POLICY_ID_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_SCOPED_POLICY_ID_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_SCOPED_POLICY_ID_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_PROCESS_TRUST_LABEL_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_PROCESS_TRUST_LABEL_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE) AceType = _TEXT("SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_PROCESS_TRUST_LABEL_ACE)SaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PSYSTEM_PROCESS_TRUST_LABEL_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PSYSTEM_PROCESS_TRUST_LABEL_ACE)SaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_PROCESS_TRUST_LABEL_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_PROCESS_TRUST_LABEL_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PSYSTEM_ACCESS_FILTER_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ACCESS_FILTER_ACE_TYPE) {
				if ((WORD)(((PSYSTEM_ACCESS_FILTER_ACE)SaclAceAddress)->Header.AceType) == SYSTEM_ACCESS_FILTER_ACE_TYPE) AceType = _TEXT("SYSTEM_ACCESS_FILTER_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PSYSTEM_ACCESS_FILTER_ACE)SaclAceAddress)->Header.AceType);
				if ((WORD)(((PSYSTEM_ACCESS_FILTER_ACE)SaclAceAddress)->Header.AceFlags) == TRUST_PROTECTED_FILTER_ACE_FLAG) AceFlag = _TEXT("TRUST_PROTECTED_FILTER_ACE_FLAG");
				else AceFlag = (LPCTSTR)(WORD)(((PSYSTEM_ACCESS_FILTER_ACE)SaclAceAddress)->Header.AceFlags);
				ConvertSidToStringSid(&((PSYSTEM_ACCESS_FILTER_ACE)SaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        SACL:ACE[") << i << _TEXT("].address: 0x") << SaclAceAddress << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceFlag: ") << AceFlag << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].AceSize: ") << ((PSYSTEM_ACCESS_FILTER_ACE)SaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            SACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PSYSTEM_ACCESS_FILTER_ACE)SaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            SACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
		}

		_tout << _TEXT("    SACL Sbz2: ") << ppSacl->Sbz2;

		if (ppSacl->AceCount == NULL) {
			Sys_SetTextColor(BLUE_INTENSITY);
			_tout << std::endl <<
				_TEXT("    DACL_REVISION: ") << (WORD)ppSacl->AclRevision << std::endl <<
				_TEXT("    DACL Sbz1: ") << (WORD)ppSacl->Sbz1 << std::endl <<
				_TEXT("    DACL size: ") << (WORD)((SIZE_T)ppSacl - (SIZE_T)ppSecurityDescriptor) * 3 << _TEXT(" bytes\n") <<
				_TEXT("    DACL:ACE count: ") << ppSacl->AceCount + 2 << std::endl <<
				_TEXT("        DACL:ACE[0].address: 0x") << (PACL)((SIZE_T)ppSacl + sizeof(SIZE_T) - (((SIZE_T)ppSacl - (SIZE_T)ppSecurityDescriptor) * 3)) << std::endl <<
				_TEXT("        DACL:ACE[1].address: 0x") << (PACL)((SIZE_T)ppSacl + sizeof(SIZE_T) + (((SIZE_T)ppSacl - (SIZE_T)ppSecurityDescriptor)) - (((SIZE_T)ppSacl - (SIZE_T)ppSecurityDescriptor) * 3)) << std::endl;
		}

		Sys_SetTextColor(FLUSH);
	}

	//================================================================================================================================================================

	if (ppDacl)
	{
		Sys_SetTextColor(BLUE_INTENSITY);
		_tout << std::endl <<
			_TEXT("    DACL_REVISION: ") << (WORD)ppDacl->AclRevision << std::endl <<
			_TEXT("    DACL Sbz1: ") << (WORD)ppDacl->Sbz1 << std::endl <<
			_TEXT("    DACL size: ") << ppDacl->AclSize << _TEXT(" bytes\n") <<
			_TEXT("    DACL:ACE count: ") << ppDacl->AceCount << std::endl;

		for (unsigned i = 0; i < ppDacl->AceCount; i++) {
			GetAce(ppDacl, i, &DaclAceAddress);
			if ((WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_ACE_TYPE) {
				if ((WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_ACE_TYPE) AceType = _TEXT("ACCESS_ALLOWED_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceType);
				if ((WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceFlags) == CRITICAL_ACE_FLAG) AceFlag = _TEXT("CRITICAL_ACE_FLAG");
				else AceFlag = (LPCTSTR)(WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceFlags);
				ConvertSidToStringSid(&((PACCESS_ALLOWED_ACE)DaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        DACL:ACE[") << i << _TEXT("].address: 0x") << DaclAceAddress << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceSize: ") << ((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PACCESS_ALLOWED_ACE)DaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PACCESS_DENIED_ACE)DaclAceAddress)->Header.AceType) == ACCESS_DENIED_ACE_TYPE) {
				if ((WORD)(((PACCESS_DENIED_ACE)DaclAceAddress)->Header.AceType) == ACCESS_DENIED_ACE_TYPE) AceType = _TEXT("ACCESS_DENIED_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PACCESS_DENIED_ACE)DaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PACCESS_DENIED_ACE)DaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        DACL:ACE[") << i << _TEXT("].address: 0x") << DaclAceAddress << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PACCESS_DENIED_ACE)DaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceSize: ") << ((PACCESS_DENIED_ACE)DaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PACCESS_DENIED_ACE)DaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_COMPOUND_ACE_TYPE) {
				if ((WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_COMPOUND_ACE_TYPE) AceType = _TEXT("ACCESS_ALLOWED_COMPOUND_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PACCESS_ALLOWED_ACE)DaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        DACL:ACE[") << i << _TEXT("].address: 0x") << DaclAceAddress << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceSize: ") << ((PACCESS_ALLOWED_ACE)DaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PACCESS_ALLOWED_ACE)DaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PACCESS_ALLOWED_OBJECT_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_OBJECT_ACE_TYPE) {
				if ((WORD)(((PACCESS_ALLOWED_OBJECT_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_OBJECT_ACE_TYPE) AceType = _TEXT("ACCESS_ALLOWED_OBJECT_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PACCESS_ALLOWED_OBJECT_ACE)DaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PACCESS_ALLOWED_OBJECT_ACE)DaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        DACL:ACE[") << i << _TEXT("].address: 0x") << DaclAceAddress << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PACCESS_ALLOWED_OBJECT_ACE)DaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceSize: ") << ((PACCESS_ALLOWED_OBJECT_ACE)DaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PACCESS_ALLOWED_OBJECT_ACE)DaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PACCESS_DENIED_OBJECT_ACE)DaclAceAddress)->Header.AceType) == ACCESS_DENIED_OBJECT_ACE_TYPE) {
				if ((WORD)(((PACCESS_DENIED_OBJECT_ACE)DaclAceAddress)->Header.AceType) == ACCESS_DENIED_OBJECT_ACE_TYPE) AceType = _TEXT("ACCESS_DENIED_OBJECT_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PACCESS_DENIED_OBJECT_ACE)DaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PACCESS_DENIED_OBJECT_ACE)DaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        DACL:ACE[") << i << _TEXT("].address: 0x") << DaclAceAddress << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PACCESS_DENIED_OBJECT_ACE)DaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceSize: ") << ((PACCESS_DENIED_OBJECT_ACE)DaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PACCESS_DENIED_OBJECT_ACE)DaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PACCESS_ALLOWED_CALLBACK_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) {
				if ((WORD)(((PACCESS_ALLOWED_CALLBACK_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) AceType = _TEXT("ACCESS_ALLOWED_CALLBACK_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PACCESS_ALLOWED_CALLBACK_ACE)DaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PACCESS_ALLOWED_CALLBACK_ACE)DaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        DACL:ACE[") << i << _TEXT("].address: 0x") << DaclAceAddress << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PACCESS_ALLOWED_CALLBACK_ACE)DaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceSize: ") << ((PACCESS_ALLOWED_CALLBACK_ACE)DaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PACCESS_ALLOWED_CALLBACK_ACE)DaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PACCESS_DENIED_CALLBACK_ACE)DaclAceAddress)->Header.AceType) == ACCESS_DENIED_CALLBACK_ACE_TYPE) {
				if ((WORD)(((PACCESS_DENIED_CALLBACK_ACE)DaclAceAddress)->Header.AceType) == ACCESS_DENIED_CALLBACK_ACE_TYPE) AceType = _TEXT("ACCESS_DENIED_CALLBACK_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PACCESS_DENIED_CALLBACK_ACE)DaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PACCESS_DENIED_CALLBACK_ACE)DaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        DACL:ACE[") << i << _TEXT("].address: 0x") << DaclAceAddress << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PACCESS_DENIED_CALLBACK_ACE)DaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceSize: ") << ((PACCESS_DENIED_CALLBACK_ACE)DaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PACCESS_DENIED_CALLBACK_ACE)DaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE) {
				if ((WORD)(((PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceType) == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE) AceType = _TEXT("ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)DaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        DACL:ACE[") << i << _TEXT("].address: 0x") << DaclAceAddress << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceSize: ") << ((PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
			if ((WORD)(((PACCESS_DENIED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceType) == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE) {
				if ((WORD)(((PACCESS_DENIED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceType) == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE) AceType = _TEXT("ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE");
				else AceType = (LPCTSTR)(WORD)(((PACCESS_DENIED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceType);
				ConvertSidToStringSid(&((PACCESS_DENIED_CALLBACK_OBJECT_ACE)DaclAceAddress)->SidStart, &SID);
				_tout <<
					_TEXT("        DACL:ACE[") << i << _TEXT("].address: 0x") << DaclAceAddress << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceType: ") << AceType << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceFlag: ") << (WORD)(((PACCESS_DENIED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceFlags) << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].AceSize: ") << ((PACCESS_DENIED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Header.AceSize << _TEXT(" bytes\n") <<
					_TEXT("            DACL:ACE[") << i << _TEXT("].Mask: 0x") << std::hex << ((PACCESS_DENIED_CALLBACK_OBJECT_ACE)DaclAceAddress)->Mask << std::dec << std::endl <<
					_TEXT("            DACL:ACE[") << i << _TEXT("]->SID: ") << SID << std::endl;
			}
		}

		_tout << _TEXT("    DACL Sbz2: ") << ppDacl->Sbz2;
		Sys_SetTextColor(FLUSH);
	}

	//================================================================================================================================================================

	ACTRLPrint(ppAuditList, ppAccessList);

	return EXIT_SUCCESS;
}