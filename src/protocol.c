/*
  Copyright 2006-2008, V.
  For contact information, see http://winaoe.org/

  This file is part of WinAoE.

  WinAoE is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  WinAoE is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with WinAoE.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "portable.h"
#include <ntddk.h>
#include <ndis.h>
#include "protocol.h"
#include "driver.h"
#include "aoe.h"

// ============================================================================

PROTOCOL_BIND_ADAPTER_EX ProtocolBindAdapterEx;
PROTOCOL_UNBIND_ADAPTER_EX ProtocolUnbindAdapterEx;
PROTOCOL_OPEN_ADAPTER_COMPLETE_EX ProtocolOpenAdapterCompleteEx;
PROTOCOL_CLOSE_ADAPTER_COMPLETE_EX ProtocolCloseAdapterCompleteEx;
PROTOCOL_NET_PNP_EVENT ProtocolNetPnpEvent;
PROTOCOL_RECEIVE_NET_BUFFER_LISTS ProtocolReceiveNetBufferLists;
PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE ProtocolSendNetBufferListsComplete;
// Optional??
SET_OPTIONS ProtocolSetOptions;
PROTOCOL_OID_REQUEST_COMPLETE ProtocolOidRequestComplete;
PROTOCOL_STATUS_EX ProtocolStatusEx;
PROTOCOL_DIRECT_OID_REQUEST_COMPLETE ProtocolDirectOidRequestComplete;


NDIS_STATUS ProtocolBindAdapterEx(IN NDIS_HANDLE ProtocolDriverContext, IN NDIS_HANDLE BindContext, IN PNDIS_BIND_PARAMETERS BindParameters);
NDIS_STATUS ProtocolUnbindAdapterEx(IN NDIS_HANDLE UnbindContext, IN NDIS_HANDLE ProtocolBindingContext);
void ProtocolOpenAdapterCompleteEx(IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS Status);
void ProtocolCloseAdapterCompleteEx(IN NDIS_HANDLE ProtocolBindingContext);
NDIS_STATUS ProtocolNetPnpEvent(IN NDIS_HANDLE ProtocolBindingContext, IN PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification);
void ProtocolReceiveNetBufferLists(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNET_BUFFER_LIST NetBufferLists,
    IN NDIS_PORT_NUMBER PortNumber,
    IN ULONG NumberOfNetBufferLists,
    IN ULONG ReceiveFlags
);
void ProtocolSendNetBufferListsComplete(IN NDIS_HANDLE ProtocolBindingContext, IN PNET_BUFFER_LIST NetBufferList, IN ULONG SendCompleteFlags);
NDIS_STATUS ProtocolSetOptions(IN NDIS_HANDLE NdisDriverHandle, IN NDIS_HANDLE DriverContext);
void ProtocolOidRequestComplete(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_OID_REQUEST OidRequest, IN NDIS_STATUS Status);
void ProtocolStatusEx(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_STATUS_INDICATION StatusIndication);
void ProtocolDirectOidRequestComplete(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_OID_REQUEST OidRequest, IN NDIS_STATUS Status);

PCHAR NetEventString(IN NET_PNP_EVENT_CODE NetEvent);

// ============================================================================

#pragma pack(1)
typedef struct _HEADER {
  UCHAR DestinationMac[6];
  UCHAR SourceMac[6];
  USHORT Protocol;
  UCHAR Data[];
} HEADER, *PHEADER;
#pragma pack()

typedef struct _PROTOBINDINGCONTEXT {
  BOOLEAN Active;
  UCHAR Mac[32]; // Why?
  ULONG MTU;
  NDIS_STATUS Status;
  NDIS_HANDLE NBLPoolHandle;
  NDIS_HANDLE NBPoolHandle;
  NDIS_HANDLE BindingHandle;
  KEVENT Event;
  BOOLEAN OutstandingRequest;
  PWCHAR AdapterName;
  PWCHAR DeviceName;
  struct _PROTOBINDINGCONTEXT*Next;
} PROTOBINDINGCONTEXT, *PPROTOBINDINGCONTEXT;

KEVENT ProtoStopEvent;
KSPIN_LOCK SpinLock;
PPROTOBINDINGCONTEXT ProtoBindingContextList = NULL;
NDIS_HANDLE ProtoHandle = NULL;

NTSTATUS ProtocolStart() {
    NDIS_STRING ProtoName;
    NDIS_PROTOCOL_DRIVER_CHARACTERISTICS ProtoChars;

    DbgPrint("ProtocolStart\n");
    KeInitializeEvent(&ProtoStopEvent, SynchronizationEvent, FALSE);
    KeInitializeSpinLock(&SpinLock);

    RtlInitUnicodeString(&ProtoName, L"AoE");

    NdisZeroMemory(&ProtoChars, sizeof(NDIS_PROTOCOL_DRIVER_CHARACTERISTICS));

    ProtoChars.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
    ProtoChars.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
    ProtoChars.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
    ProtoChars.MajorNdisVersion = 6;
    ProtoChars.MinorNdisVersion = 30;
    ProtoChars.MajorDriverVersion = 1;
    ProtoChars.MinorDriverVersion = 0;
    ProtoChars.Flags = 0;
    ProtoChars.Name = ProtoName;
    ProtoChars.BindAdapterHandlerEx = ProtocolBindAdapterEx;
    ProtoChars.UnbindAdapterHandlerEx = ProtocolUnbindAdapterEx;
    ProtoChars.OpenAdapterCompleteHandlerEx = ProtocolOpenAdapterCompleteEx;
    ProtoChars.CloseAdapterCompleteHandlerEx = ProtocolCloseAdapterCompleteEx;
    ProtoChars.NetPnPEventHandler = ProtocolNetPnpEvent;
    ProtoChars.UninstallHandler = NULL;
    ProtoChars.ReceiveNetBufferListsHandler = ProtocolReceiveNetBufferLists;
    ProtoChars.SendNetBufferListsCompleteHandler = ProtocolSendNetBufferListsComplete;
    ProtoChars.SetOptionsHandler = ProtocolSetOptions;
    ProtoChars.OidRequestCompleteHandler = ProtocolOidRequestComplete;
    ProtoChars.StatusHandlerEx = ProtocolStatusEx;
    ProtoChars.DirectOidRequestCompleteHandler = ProtocolDirectOidRequestComplete;

    return NdisRegisterProtocolDriver(NULL, &ProtoChars, &ProtoHandle);
}

VOID ProtocolStop() {

    DbgPrint("ProtocolStop\n");

    KeResetEvent(&ProtoStopEvent);

    if (ProtoHandle != NULL) {
        NdisDeregisterProtocolDriver(ProtoHandle);
    }
    if (ProtoBindingContextList != NULL) KeWaitForSingleObject(&ProtoStopEvent, Executive, KernelMode, FALSE, NULL);
}

BOOLEAN ProtocolSearchNIC(IN PUCHAR Mac) {
    PPROTOBINDINGCONTEXT Context = ProtoBindingContextList;

    DbgPrint("ProtocolSearchNIC\n");

    while (Context != NULL) {
        if (RtlCompareMemory(Mac, Context->Mac, 6) == 6) break;
        Context = Context->Next;
    }
    if (Context != NULL) return TRUE;
    return FALSE;
}

ULONG ProtocolGetMTU(IN PUCHAR Mac) {
    PPROTOBINDINGCONTEXT Context = ProtoBindingContextList;

    DbgPrint("ProtocolGetMTU\n");

    while (Context != NULL) {
        if (RtlCompareMemory(Mac, Context->Mac, 6) == 6) break;
        Context = Context->Next;
    }
    if (Context == NULL) return 0;
    return Context->MTU;
}

NDIS_STATUS ProtocolBindAdapterEx(IN NDIS_HANDLE ProtocolDriverContext, IN NDIS_HANDLE BindContext, IN PNDIS_BIND_PARAMETERS BindParameters)
{
    PPROTOBINDINGCONTEXT Context, Walker;
    NET_BUFFER_LIST_POOL_PARAMETERS NBLPoolParams;
    NET_BUFFER_POOL_PARAMETERS NBPoolParams;
    NDIS_OPEN_PARAMETERS ProtoOpenParams;
    NDIS_STATUS Status;
    NDIS_MEDIUM MediumArray[] = { NdisMedium802_3 };
    UINT SelectedMediumIndex;
    NET_FRAME_TYPE FrameTypeArray[] = { AOEPROTOCOLID };
    NDIS_STRING AdapterInstanceName;
    KIRQL Irql;

    UNREFERENCED_PARAMETER(ProtocolDriverContext);

    DbgPrint("ProtocolBindAdapterEx\n");

    if ((Context = (NDIS_HANDLE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROTOBINDINGCONTEXT), 'PBAE')) == NULL) {
        DbgPrint("ProtocolBindAdapter ExAllocatePool2\n");
        return NDIS_STATUS_RESOURCES;
    }

    Context->Next = NULL;
    KeInitializeEvent(&Context->Event, SynchronizationEvent, FALSE);

    NBLPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    NBLPoolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    NBLPoolParams.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    NBLPoolParams.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    NBLPoolParams.fAllocateNetBuffer = TRUE;
    NBLPoolParams.ContextSize = 0;
    NBLPoolParams.PoolTag = 'AoE';
    NBLPoolParams.DataSize = 0;

    NBPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    NBPoolParams.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    NBPoolParams.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    NBPoolParams.PoolTag = 'AoE';
    NBPoolParams.DataSize = 0;

    Context->NBLPoolHandle = NdisAllocateNetBufferListPool(Context->BindingHandle, &NBLPoolParams);
    if (Context->NBLPoolHandle == NULL) {
        DbgPrint("ProtocolBindAdapter NdisAllocateNetBufferListPool");
        ExFreePool(Context);
        return NDIS_STATUS_RESOURCES;
    }

    Context->NBPoolHandle = NdisAllocateNetBufferPool(Context->BindingHandle, &NBPoolParams);
    if (Context->NBPoolHandle == NULL) {
        DbgPrint("ProtocolBindAdapter NdisAllocateNetBufferPool");
        NdisFreeNetBufferListPool(Context->NBLPoolHandle);
        ExFreePool(Context);
        return NDIS_STATUS_RESOURCES;
    }

    ProtoOpenParams.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
    ProtoOpenParams.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
    ProtoOpenParams.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVISION_1;
    ProtoOpenParams.AdapterName = BindParameters->AdapterName;
    ProtoOpenParams.MediumArray = MediumArray;
    ProtoOpenParams.MediumArraySize = (sizeof(MediumArray) / sizeof(NDIS_MEDIUM));
    ProtoOpenParams.SelectedMediumIndex = &SelectedMediumIndex;
    ProtoOpenParams.FrameTypeArray = FrameTypeArray;
    ProtoOpenParams.FrameTypeArraySize = (sizeof(FrameTypeArray) / sizeof(NET_FRAME_TYPE));

    Status = NdisOpenAdapterEx(ProtoHandle, Context, &ProtoOpenParams, BindContext, &Context->BindingHandle);
    DbgPrint("NdisOpenAdapterEx 0x%08x\n", Status);
    if(!NT_SUCCESS(Status)){
        DbgPrint("ProtocolBindAdapterEx NdisOpenAdapterEx 0x%08x\n", Status);
        NdisFreeNetBufferPool(Context->NBPoolHandle);
        DbgPrint("NBPool freed\n");
        NdisFreeNetBufferListPool(Context->NBLPoolHandle);
        DbgPrint("NBLPool freed\n");
        ExFreePool(Context->AdapterName);
        DbgPrint("AdapterName freed\n");
        ExFreePool(Context->DeviceName);
        DbgPrint("DeviceName freed\n");
        ExFreePool(Context);
        DbgPrint("Context freed\nReturning...\n");
        return Status;
    }
    if (SelectedMediumIndex != 0) DbgPrint("ProtocolBindAdapterEx SelectedMediumIndex: %d\n", SelectedMediumIndex);

    Context->AdapterName = NULL;
    if (NT_SUCCESS(Status = NdisQueryAdapterInstanceName(&AdapterInstanceName, Context->BindingHandle))) {
        if ((Context->AdapterName = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, AdapterInstanceName.Length + sizeof(WCHAR), 'PBAE')) == NULL) {
            DbgPrint("ProtocolBindAdapter ExAllocatePool2 AdapterName\n");
        }
        else {
            RtlZeroMemory(Context->AdapterName, AdapterInstanceName.Length + sizeof(WCHAR));
            RtlCopyMemory(Context->AdapterName, AdapterInstanceName.Buffer, AdapterInstanceName.Length);
        }
        NdisFreeMemory(AdapterInstanceName.Buffer, 0, 0);
    }
    else {
        Error("ProtocolBindAdapter NdisQueryAdapterInstanceName", Status);
    }

    Context->DeviceName = NULL;
    if (BindParameters->AdapterName->Length > 0) {
        if ((Context->DeviceName = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, BindParameters->AdapterName->Length + sizeof(WCHAR), 'PBAE')) == NULL) {
            DbgPrint("ProtocolBindAdapter ExAllocatePool2 DeviceName\n");
        }
        else {
            RtlZeroMemory(Context->DeviceName, BindParameters->AdapterName->Length + sizeof(WCHAR));
            RtlCopyMemory(Context->DeviceName, BindParameters->AdapterName->Buffer, BindParameters->AdapterName->Length);
        }
    }

    if (Context->AdapterName != NULL) DbgPrint("Adapter: %S\n", Context->AdapterName);
    if (Context->DeviceName != NULL) DbgPrint("Device Name: %S\n", Context->DeviceName);
    if ((Context->AdapterName == NULL) && (Context->DeviceName == NULL)) DbgPrint("Unnamed Adapter...\n");

    RtlCopyMemory(Context->Mac, BindParameters->CurrentMacAddress, sizeof(BindParameters->CurrentMacAddress));
    KdPrint(("Mac: %02X:%02X:%02X:%02X:%02X:%02X\n", 
        Context->Mac[0], Context->Mac[1],  Context->Mac[2], 
        Context->Mac[3], Context->Mac[4], Context->Mac[5]));

    Context->MTU = BindParameters->MtuSize;
    DbgPrint("MTU: %d\n", Context->MTU);

    NDIS_OID_REQUEST Request;
    ULONG InformationBuffer = NDIS_PACKET_TYPE_DIRECTED;
    Request.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    Request.Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    Request.Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;
    Request.RequestType = NdisRequestSetInformation;
    Request.DATA.SET_INFORMATION.Oid = OID_GEN_CURRENT_PACKET_FILTER;
    Request.DATA.SET_INFORMATION.InformationBuffer = &InformationBuffer;
    Request.DATA.SET_INFORMATION.InformationBufferLength = sizeof(InformationBuffer);

    KeResetEvent(&Context->Event);
    Status = NdisOidRequest(Context->BindingHandle, &Request);
    if (Status == NDIS_STATUS_PENDING) {
        KeWaitForSingleObject(&Context->Event, Executive, KernelMode, FALSE, NULL);
        Status = Context->Status;
    }
    if (!NT_SUCCESS(Status)) Error("ProtocolBindAdapter NdisRequest (filter)", Status);

    KeAcquireSpinLock(&SpinLock, &Irql);
    if (ProtoBindingContextList == NULL) {
        ProtoBindingContextList = Context;
    }
    else {
        for (Walker = ProtoBindingContextList; Walker->Next != NULL; Walker = Walker->Next);
        Walker->Next = Context;
    }
    KeReleaseSpinLock(&SpinLock, Irql);

    AoEResetProbe();
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS ProtocolUnbindAdapterEx(IN NDIS_HANDLE UnbindContext, IN NDIS_HANDLE ProtocolBindingContext)
{
    PPROTOBINDINGCONTEXT Context = ProtocolBindingContext;
    PPROTOBINDINGCONTEXT Walker, PreviousContext;
    NDIS_STATUS Status;
    KIRQL Irql;

    UNREFERENCED_PARAMETER(UnbindContext);

    DbgPrint("ProtocolUnbindAdapterEx\n");

    PreviousContext = NULL;
    KeAcquireSpinLock(&SpinLock, &Irql);
    for (Walker = ProtoBindingContextList; Walker != Context && Walker != NULL; Walker = Walker->Next) PreviousContext = Walker;
    if (Walker == NULL) {
        DbgPrint("Context not found in ProtoBindingContextList!!\n");
        KeReleaseSpinLock(&SpinLock, Irql);
        return NDIS_STATUS_SUCCESS;
    }
    if (PreviousContext == NULL) {
        ProtoBindingContextList = Walker->Next;
    }
    else {
        PreviousContext->Next = Walker->Next;
    }
    KeReleaseSpinLock(&SpinLock, Irql);

    Status = NdisCloseAdapterEx(Context->BindingHandle);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("NdisCloseAdapterEx pending 0x%08x\n", Status);
    }
    NdisFreeNetBufferPool(Context->NBPoolHandle);
    NdisFreeNetBufferListPool(Context->NBLPoolHandle);
    ExFreePool(Context);
    if (ProtoBindingContextList == NULL) KeSetEvent(&ProtoStopEvent, 0, FALSE);
    return NDIS_STATUS_SUCCESS;
}

void ProtocolOpenAdapterCompleteEx(IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS Status)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    DbgPrint("ProtocolOpenAdapterCompleteEx: 0x%08x\n", Status);
}

void ProtocolCloseAdapterCompleteEx(IN NDIS_HANDLE ProtocolBindingContext)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    DbgPrint("ProtocolCloseAdapterCompleteEx\n");
}

NDIS_STATUS ProtocolNetPnpEvent(IN NDIS_HANDLE ProtocolBindingContext, IN PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification)
{
    DbgPrint("ProtocolNetPnpEvent: %s\n", NetEventString(NetPnPEventNotification->NetPnPEvent.NetEvent));

    if (ProtocolBindingContext == NULL && NetPnPEventNotification->NetPnPEvent.NetEvent == NetEventReconfigure) {
        NdisReEnumerateProtocolBindings(ProtoHandle);
    }
    if (NetPnPEventNotification->NetPnPEvent.NetEvent == NetEventQueryRemoveDevice) {
        return NDIS_STATUS_FAILURE;
    }
    else {
        return NDIS_STATUS_SUCCESS;
    }
}

BOOLEAN ProtocolSend(IN PUCHAR SourceMac, IN PUCHAR DestinationMac, IN PUCHAR Data, IN ULONG DataSize, IN PVOID PacketContext)
{
    PPROTOBINDINGCONTEXT Context = ProtoBindingContextList;
    PHEADER DataBuffer;
    PNET_BUFFER_LIST NBList;
    PMDL pMdl = NULL;
    PHEADER pHead = NULL;
    ULONG pLen = 0;

    //DbgPrint("\nProtocolSend\n");

    if (RtlCompareMemory(SourceMac, "\xff\xff\xff\xff\xff\xff", 6) == 6) {
        while (Context != NULL) {
            ProtocolSend(Context->Mac, DestinationMac, Data, DataSize, NULL);
            Context = Context->Next;
        }
        return TRUE;
    }

    while (Context != NULL) {
        if (RtlCompareMemory(SourceMac, Context->Mac, 6) == 6) break;
        Context = Context->Next;
    }
    if (Context == NULL) {
        DbgPrint("ProtocolSend Can't find NIC %02x:%02x:%02x:%02x:%02x:%02x\n", SourceMac[0], SourceMac[1], SourceMac[2], SourceMac[3], SourceMac[4], SourceMac[5]);
        return FALSE;
    }

    if (DataSize > Context->MTU) {
        DbgPrint("ProtocolSend Tried to send oversized packet (size: %d, MTU: %d)\n", DataSize, Context->MTU);
        return FALSE;
    }

    if ((DataBuffer = (PHEADER)ExAllocatePool2(POOL_FLAG_NON_PAGED, (sizeof(HEADER) + DataSize), 'PrSe')) == NULL) {
        DbgPrint("ProtocolSend ExAllocatePool2\n");
        return FALSE;
    }
    
    RtlCopyMemory(DataBuffer->SourceMac, SourceMac, 6);
    RtlCopyMemory(DataBuffer->DestinationMac, DestinationMac, 6);
    DataBuffer->Protocol = htons(AOEPROTOCOLID);
    RtlCopyMemory(DataBuffer->Data, Data, DataSize);

    pMdl = NdisAllocateMdl(Context->BindingHandle, DataBuffer, sizeof(HEADER) + DataSize);
    if (pMdl == NULL) {
        DbgPrint("ProtocolSend NdisAllocateMdl\n");
        return FALSE;
    }
    ExFreePool(DataBuffer);
    NdisQueryMdl(pMdl, &pHead, &pLen, NormalPagePriority | MdlMappingNoExecute);
    if (pHead == NULL) {
        DbgPrint("ProtocolSend NdisQueryMdl\n");
        return FALSE;
    }
    /*KdPrint(("Send Header: %x:%x:%x:%x:%x:%x %x %x:%x:%x:%x:%x:%x\n", pHead->DestinationMac[0], pHead->DestinationMac[1], pHead->DestinationMac[2],
        pHead->DestinationMac[3], pHead->DestinationMac[4], pHead->DestinationMac[5], pHead->Protocol, pHead->SourceMac[0], pHead->SourceMac[1], pHead->SourceMac[2], 
        pHead->SourceMac[3], pHead->SourceMac[4], pHead->SourceMac[5]));
    DbgPrint("Send Length: %d\n", pLen);

    DbgPrint("Send Data: ");
    for (UINT i = 0; i < sizeof(pHead->DestinationMac); i++) {
        DbgPrint("%02x ", pHead->DestinationMac[i]);
    }
    for (UINT i = 0; i < sizeof(pHead->SourceMac); i++) {
        DbgPrint("%02x ", pHead->SourceMac[i]);
    }
    DbgPrint("%02x ", pHead->Protocol);
    for (UINT i = 0; i < pLen - sizeof(pHead->DestinationMac) - sizeof(pHead->SourceMac) - sizeof(pHead->Protocol); i++) {
        DbgPrint("%02x ", pHead->Data[i]);
    }
    DbgPrint("\n");*/

    NBList = NdisAllocateNetBufferAndNetBufferList(Context->NBLPoolHandle, 0, 0, pMdl, 0, pLen);
    if (NBList == NULL) {
        DbgPrint("ProtocolSend NdisAllocateNetBufferAndNetBufferList\n");
        return FALSE;
    }

    NBList->SourceHandle = Context->BindingHandle;
    *(PVOID*)NBList->FirstNetBuffer->ProtocolReserved = PacketContext;
    //DbgPrint("IRQL: %d\n", KeGetCurrentIrql());

    UINT SendFlags = 0;
    if (KeGetCurrentIrql() == DISPATCH_LEVEL)
        SendFlags = NDIS_SEND_FLAGS_DISPATCH_LEVEL;
    NdisSendNetBufferLists(Context->BindingHandle, NBList, NDIS_DEFAULT_PORT_NUMBER, SendFlags);

    return TRUE;
}

void ProtocolReceiveNetBufferLists(IN NDIS_HANDLE ProtocolBindingContext, IN PNET_BUFFER_LIST NetBufferLists, IN NDIS_PORT_NUMBER PortNumber, IN ULONG NumberOfNetBufferLists, IN ULONG ReceiveFlags)
{
    PPROTOBINDINGCONTEXT Context = ProtocolBindingContext;
    PNET_BUFFER_LIST pNetBufList;
    PMDL pMdl = NULL;
    PHEADER Header = NULL;
    ULONG pLen = 0;
    ULONG DataLength = 0;
    UINT ReturnFlags = 0;

    UNREFERENCED_PARAMETER(ReceiveFlags);
    UNREFERENCED_PARAMETER(PortNumber);

    if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags)) {
        NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
    }

    //DbgPrint("\nProtocolReceiveNetBufferLists: %d\n", NumberOfNetBufferLists);

    pNetBufList = NetBufferLists;

    for (USHORT i = 0; pNetBufList != NULL; i++) {
        NBL_CLEAR_PROTOCOL_RSVD_FLAG(pNetBufList, NBL_PROT_RSVD_FLAGS);

        pMdl = pNetBufList->FirstNetBuffer->CurrentMdl;
        ASSERT(pMdl != NULL);
        if(pMdl->Next != NULL)
            DbgPrint("\nDEBUG: Next MDL in chain not null!");
        if (pMdl) {
            NdisQueryMdl(pMdl, &Header, &pLen, NormalPagePriority | MdlMappingNoExecute);
        }
        DataLength = pNetBufList->FirstNetBuffer->DataLength - 4;
        if (Header != NULL) {
            /*DbgPrint("\nNetBufferList %d\n", i + 1);
            KdPrint(("Recv Header: %x:%x:%x:%x:%x:%x %x %x:%x:%x:%x:%x:%x\n", Header->DestinationMac[0], Header->DestinationMac[1], Header->DestinationMac[2],
                Header->DestinationMac[3], Header->DestinationMac[4], Header->DestinationMac[5], Header->Protocol, Header->SourceMac[0], Header->SourceMac[1], Header->SourceMac[2],
                Header->SourceMac[3], Header->SourceMac[4], Header->SourceMac[5]));
            DbgPrint("Recv Length: %d\n", DataLength);
            DbgPrint("Recv Data: ");
            for (UINT i = 0; i < sizeof(Header->DestinationMac); i++) {
                DbgPrint("%02x ", Header->DestinationMac[i]);
            }
            for (UINT i = 0; i < sizeof(Header->SourceMac); i++) {
                DbgPrint("%02x ", Header->SourceMac[i]);
            }
            DbgPrint("%02x ", Header->Protocol);
            for (UINT i = 0; i < DataLength - sizeof(Header->DestinationMac) - sizeof(Header->SourceMac) - sizeof(Header->Protocol); i++) {
                DbgPrint("%02x ", Header->Data[i]);
            }
            DbgPrint("\n");*/
            if (ntohs(Header->Protocol) != AOEPROTOCOLID) {
                DbgPrint("NetBufferList %d not AoE; rejected\n", i+1);
            }
            else {
                //DbgPrint("NetBufferList %d received\n", i+1);
                AoEReply(Header->SourceMac, Header->DestinationMac, (PUCHAR)&Header->Data,
                    DataLength - sizeof(Header->SourceMac) - sizeof(Header->DestinationMac) - sizeof(Header->Protocol));
            }
        }

        pNetBufList = pNetBufList->Next;
    }
    NdisReturnNetBufferLists(Context->BindingHandle, NetBufferLists, ReturnFlags);
}

void ProtocolSendNetBufferListsComplete(IN NDIS_HANDLE ProtocolBindingContext, IN PNET_BUFFER_LIST NetBufferList, IN ULONG SendCompleteFlags)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(SendCompleteFlags);
    //DbgPrint("\nProtocolSendNetBufferListsComplete: 0x%08X\n", NetBufferList->Status);

    NdisFreeNetBufferList(NetBufferList);
}

NDIS_STATUS ProtocolSetOptions(IN NDIS_HANDLE NdisDriverHandle, IN NDIS_HANDLE DriverContext)
{
    UNREFERENCED_PARAMETER(NdisDriverHandle);
    UNREFERENCED_PARAMETER(DriverContext);
    DbgPrint("ProtocolSetOptions\n");
    return NDIS_STATUS_SUCCESS;
}

void ProtocolOidRequestComplete(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_OID_REQUEST OidRequest, IN NDIS_STATUS Status)
{
    PPROTOBINDINGCONTEXT Context = ProtocolBindingContext;

    UNREFERENCED_PARAMETER(OidRequest);

    DbgPrint("ProtocolOidRequestComplete: 0x%08X\n", Status);

    Context->Status = Status;
    KeSetEvent(&Context->Event, 0, FALSE);
}

void ProtocolStatusEx(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_STATUS_INDICATION StatusIndication)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    DbgPrint("ProtocolStatusEx: 0x%08X\n", StatusIndication->StatusCode);
}

void ProtocolDirectOidRequestComplete(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_OID_REQUEST OidRequest, IN NDIS_STATUS Status)
{
    UNREFERENCED_PARAMETER(OidRequest);
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    DbgPrint("ProtocolDirectOidRequestComplete: %d\n", Status);
}

PCHAR NetEventString(IN NET_PNP_EVENT_CODE NetEvent) {
    switch (NetEvent) {
    case NetEventSetPower:             return "NetEventSetPower";
    case NetEventQueryPower:           return "NetEventQueryPower";
    case NetEventQueryRemoveDevice:    return "NetEventQueryRemoveDevice";
    case NetEventCancelRemoveDevice:   return "NetEventCancelRemoveDevice";
    case NetEventReconfigure:          return "NetEventReconfigure";
    case NetEventBindList:             return "NetEventBindList";
    case NetEventBindsComplete:        return "NetEventBindsComplete";
    case NetEventPnPCapabilities:      return "NetEventPnPCapabilities";
    case NetEventPause:                return "NetEventPause";
    case NetEventRestart:              return "NetEventRestart";
    case NetEventPortActivation:       return "NetEventPortActivation";
    case NetEventPortDeactivation:     return "NetEventPortDeactivation";
    case NetEventIMReEnableDevice:     return "NetEventIMReEnableDevice";
    case NetEventNDKEnable:            return "NetEventNDKEnable";
    case NetEventNDKDisable:           return "NetEventNDKDisable";
    case NetEventFilterPreDetach:      return "NetEventFilterPreDetach";
    case NetEventBindFailed:           return "NetEventBindFailed";
    case NetEventSwitchActivate:       return "NetEventSwitchActivate";
    case NetEventAllowBindsAbove:      return "NetEventAllowBindsAbove";
    case NetEventInhibitBindsAbove:    return "NetEventInhibitBindsAbove";
    case NetEventAllowStart:           return "NetEventAllowStart";
    case NetEventRequirePause:         return "NetEventRequirePause";
    case NetEventUploadGftFlowEntries: return "NetEventUploadGftFlowEntries";
    case NetEventMaximum:              return "NetEventMaximum";
    default:                           return "NetEventUnknown";
    }
}