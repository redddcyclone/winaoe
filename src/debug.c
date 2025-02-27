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
#include <srb.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntddstor.h>
#include <ntdddisk.h>
// #include <ndis.h>
#include "driver.h"
#include "mount.h"

typedef struct _IRPLIST {
  PIRP Irp;
  ULONG Number;
  PCHAR DebugMessage;
  struct _IRPLIST *Next;
  struct _IRPLIST *Previous;
} IRPLIST, *PIRPLIST;

PIRPLIST IrpList = NULL;
KSPIN_LOCK SpinLock;
LONG Number = 0;

extern int sprintf(char*, const char *, ...);

// in this file
PIRPLIST STDCALL IrpListRecord(IN PIRP Irp);
VOID STDCALL DecodeIrp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PCHAR DebugMessage);
PCHAR STDCALL MajorFunctionString(IN UCHAR MajorFunction);
PCHAR STDCALL PnPMinorFunctionString(IN UCHAR MinorFunction);
PCHAR STDCALL SystemControlMinorFunctionString(IN UCHAR MinorFunction);
PCHAR STDCALL PowerMinorFunctionString(IN UCHAR MinorFunction);
PCHAR STDCALL QueryDeviceRelationsString(IN DEVICE_RELATION_TYPE Type);
PCHAR STDCALL QueryIdString(IN BUS_QUERY_ID_TYPE IdType);
PCHAR STDCALL SrbFunctionString(IN UCHAR Function);
PCHAR STDCALL DeviceIoControlString(IN ULONG IoControlCode);
PCHAR STDCALL DeviceTextTypeString(IN DEVICE_TEXT_TYPE DeviceTextType);
PCHAR STDCALL SCSIOPString(IN UCHAR OperationCode);

VOID STDCALL InitializeDebug() {
  KeInitializeSpinLock(&SpinLock);
}

PIRPLIST STDCALL IrpListRecord(IN PIRP Irp) {
  PIRPLIST Record;
  KIRQL Irql;

  KeAcquireSpinLock(&SpinLock, &Irql);
  Record = IrpList;
  while (Record != NULL && Record->Irp != Irp) Record = Record->Next;
  KeReleaseSpinLock(&SpinLock, Irql);
  return Record;
}

VOID STDCALL DebugIrpStart(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
  PCHAR DebugMessage;
  PIRPLIST Record, Temp;
  KIRQL Irql;

  if ((DebugMessage = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, 'DeIS')) == NULL) {
    DbgPrint("DebugIrpStart ExAllocatePool2 DebugMessage\n");
  }
  DecodeIrp(DeviceObject, Irp, DebugMessage);
  if ((Record = (PIRPLIST)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IRPLIST), 'DeIS')) == NULL) {
    DbgPrint("DebugIrpStart ExAllocatePool2 Record\n");
    DbgPrint("IRP %s\n", DebugMessage);
  }
  Record->Next = NULL;
  Record->Previous = NULL;
  Record->Irp = Irp;
  Record->DebugMessage = DebugMessage;
  Record->Number = InterlockedIncrement(&Number);;
  KeAcquireSpinLock(&SpinLock, &Irql);
  if (IrpList == NULL) {
    IrpList = Record;
    Record->Previous = NULL;
  } else {
    Temp = IrpList;
    while (Temp->Next != NULL) Temp = Temp->Next;
    Temp->Next = Record;
    Record->Previous = Temp;
  }
  KeReleaseSpinLock(&SpinLock, Irql);
  DbgPrint("IRP %d: %s\n", Record->Number, Record->DebugMessage);
}

VOID STDCALL DebugIrpEnd(IN PIRP Irp, IN NTSTATUS Status) {
  PIRPLIST Record;
  KIRQL Irql;

  if ((Record = IrpListRecord(Irp)) == NULL) {
    DbgPrint("Irp not found in IrpList!! (returned 0x%08x, Status)\n");
    return;
  }
  // There is no race condition between getting the record and unlinking in IrpList, unless DebugIrpEnd
  // is called more than once on an irp (which itself is a bug, it should only be called one time).
  KeAcquireSpinLock(&SpinLock, &Irql);
  if (Record->Previous == NULL) {
    IrpList = Record->Next;
  } else {
    Record->Previous->Next = Record->Next;
  }
  if (Record->Next != NULL) {
    Record->Next->Previous = Record->Previous;
  }
  KeReleaseSpinLock(&SpinLock, Irql);

  DbgPrint("IRP %d: %s -> 0x%08x\n", Record->Number, Record->DebugMessage, Status);
  ExFreePool(Record->DebugMessage);
  ExFreePool(Record);
}

VOID STDCALL DecodeIrp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PCHAR DebugMessage) {
  PDEVICEEXTENSION DeviceExtension = (PDEVICEEXTENSION)DeviceObject->DeviceExtension;
  PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
  PSCSI_REQUEST_BLOCK Srb;
  PCDB Cdb;
  ULONG StartSector, SectorCount;
  PSTORAGE_PROPERTY_QUERY StoragePropertyQuery;

  sprintf(DebugMessage, "%s %s", (DeviceExtension->IsBus?"Bus":"Disk"), MajorFunctionString(Stack->MajorFunction));
  switch (Stack->MajorFunction) {
    case IRP_MJ_SYSTEM_CONTROL:
      sprintf(DebugMessage, "%s %s", DebugMessage, SystemControlMinorFunctionString(Stack->MinorFunction));
      break;
    case IRP_MJ_PNP:
      sprintf(DebugMessage, "%s %s", DebugMessage, PnPMinorFunctionString(Stack->MinorFunction));
      switch (Stack->MinorFunction) {
        case IRP_MN_QUERY_ID:
          sprintf(DebugMessage, "%s %s", DebugMessage, QueryIdString(Stack->Parameters.QueryId.IdType));
          break;
        case IRP_MN_QUERY_DEVICE_TEXT:
          sprintf(DebugMessage, "%s %s", DebugMessage, DeviceTextTypeString(Stack->Parameters.QueryDeviceText.DeviceTextType));
          break;
        case IRP_MN_QUERY_DEVICE_RELATIONS:
          sprintf(DebugMessage, "%s %s", DebugMessage, QueryDeviceRelationsString(Stack->Parameters.QueryDeviceRelations.Type));
          break;
      }
      break;
    case IRP_MJ_DEVICE_CONTROL:
      sprintf(DebugMessage, "%s (0x%08x) %s", DebugMessage, (int)Stack->Parameters.DeviceIoControl.IoControlCode, DeviceIoControlString(Stack->Parameters.DeviceIoControl.IoControlCode));
      if (!DeviceExtension->IsBus && Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {
        StoragePropertyQuery = Irp->AssociatedIrp.SystemBuffer;
        switch (StoragePropertyQuery->PropertyId) {
          case StorageDeviceProperty:  sprintf(DebugMessage, "%s StorageDeviceProperty", DebugMessage); break;
          case StorageAdapterProperty: sprintf(DebugMessage, "%s StorageAdapterProperty", DebugMessage); break;
          default:                     sprintf(DebugMessage, "%s StorageUnknownProperty (%d)", DebugMessage, StoragePropertyQuery->PropertyId);
        }
        switch (StoragePropertyQuery->QueryType) {
          case PropertyStandardQuery: sprintf(DebugMessage, "%s PropertyStandardQuery", DebugMessage); break;
          case PropertyExistsQuery:   sprintf(DebugMessage, "%s PropertyExistsQuery", DebugMessage); break;
          default:                    sprintf(DebugMessage, "%s PropertyUnknownQuery (%d)", DebugMessage, StoragePropertyQuery->QueryType);
        }
      }
      break;
    case IRP_MJ_SCSI:
      if (!DeviceExtension->IsBus) {
        Srb = Stack->Parameters.Scsi.Srb;
        Cdb = (PCDB)Srb->Cdb;
        sprintf(DebugMessage, "%s %s", DebugMessage, SrbFunctionString(Srb->Function));
        if (Srb->Lun == 0 && Srb->Function == SRB_FUNCTION_EXECUTE_SCSI) {
          sprintf(DebugMessage, "%s %s", DebugMessage, SCSIOPString(Cdb->AsByte[0]));
          if (Cdb->AsByte[0] == SCSIOP_READ || Cdb->AsByte[0] == SCSIOP_WRITE || Cdb->AsByte[0] == SCSIOP_VERIFY) {
            StartSector = (Cdb->CDB10.LogicalBlockByte0 << 24) + (Cdb->CDB10.LogicalBlockByte1 << 16) + (Cdb->CDB10.LogicalBlockByte2 << 8) + Cdb->CDB10.LogicalBlockByte3;
            SectorCount = (Cdb->CDB10.TransferBlocksMsb << 8 ) + Cdb->CDB10.TransferBlocksLsb;
            sprintf(DebugMessage, "%s %d %d", DebugMessage, (int)StartSector, (int)SectorCount);
          }
          if (Cdb->AsByte[0] == SCSIOP_READ || Cdb->AsByte[0] == SCSIOP_WRITE) {
            sprintf(DebugMessage, "%s (buffersize: %d)", DebugMessage, (int)Srb->DataTransferLength);
          }
        }
      }
      break;
  }
}

PCHAR STDCALL MajorFunctionString(IN UCHAR MajorFunction) {
  switch (MajorFunction) {
    case IRP_MJ_CREATE:                   return "CREATE";
//    case IRP_MJ_NAMED_PIPE:               return "NAMED_PIPE";
    case IRP_MJ_CLOSE:                    return "CLOSE";
    case IRP_MJ_READ:                     return "READ";
    case IRP_MJ_WRITE:                    return "WRITE";
    case IRP_MJ_QUERY_INFORMATION:        return "QUERY_INFORMATION";
    case IRP_MJ_SET_INFORMATION:          return "SET_INFORMATION";
    case IRP_MJ_QUERY_EA:                 return "QUERY_EA";
    case IRP_MJ_SET_EA:                   return "SET_EA";
    case IRP_MJ_FLUSH_BUFFERS:            return "FLUSH_BUFFERS";
    case IRP_MJ_QUERY_VOLUME_INFORMATION: return "QUERY_VOLUME_INFORMATION";
    case IRP_MJ_SET_VOLUME_INFORMATION:   return "SET_VOLUME_INFORMATION";
    case IRP_MJ_DIRECTORY_CONTROL:        return "DIRECTORY_CONTROL";
    case IRP_MJ_FILE_SYSTEM_CONTROL:      return "FILE_SYSTEM_CONTROL";
    case IRP_MJ_DEVICE_CONTROL:           return "DEVICE_CONTROL";
//    case IRP_MJ_INTERNAL_DEVICE_CONTROL:  return "INTERNAL_DEVICE_CONTROL";
    case IRP_MJ_SCSI:                     return "SCSI";
    case IRP_MJ_SHUTDOWN:                 return "SHUTDOWN";
    case IRP_MJ_LOCK_CONTROL:             return "LOCK_CONTROL";
    case IRP_MJ_CLEANUP:                  return "CLEANUP";
    case IRP_MJ_CREATE_MAILSLOT:          return "CREATE_MAILSLOT";
    case IRP_MJ_QUERY_SECURITY:           return "QUERY_SECURITY";
    case IRP_MJ_SET_SECURITY:             return "SET_SECURITY";
    case IRP_MJ_POWER:                    return "POWER";
    case IRP_MJ_SYSTEM_CONTROL:           return "SYSTEM_CONTROL";
    case IRP_MJ_DEVICE_CHANGE:            return "DEVICE_CHANGE";
    case IRP_MJ_QUERY_QUOTA:              return "QUERY_QUOTA";
    case IRP_MJ_SET_QUOTA:                return "SET_QUOTA";
    case IRP_MJ_PNP:                      return "PNP";
//    case IRP_MJ_PNP_POWER:                return "PNP_POWER";
//    case IRP_MJ_MAXIMUM_FUNCTION:         return "MAXIMUM_FUNCTION";
    default:                              return "UNKNOWN";
  }
}

PCHAR STDCALL PnPMinorFunctionString(IN UCHAR MinorFunction) {
  switch (MinorFunction) {
    case IRP_MN_START_DEVICE:                 return "START_DEVICE";
    case IRP_MN_QUERY_REMOVE_DEVICE:          return "QUERY_REMOVE_DEVICE";
    case IRP_MN_REMOVE_DEVICE:                return "REMOVE_DEVICE";
    case IRP_MN_CANCEL_REMOVE_DEVICE:         return "CANCEL_REMOVE_DEVICE";
    case IRP_MN_STOP_DEVICE:                  return "STOP_DEVICE";
    case IRP_MN_QUERY_STOP_DEVICE:            return "QUERY_STOP_DEVICE";
    case IRP_MN_CANCEL_STOP_DEVICE:           return "CANCEL_STOP_DEVICE";
    case IRP_MN_QUERY_DEVICE_RELATIONS:       return "QUERY_DEVICE_RELATIONS";
    case IRP_MN_QUERY_INTERFACE:              return "QUERY_INTERFACE";
    case IRP_MN_QUERY_CAPABILITIES:           return "QUERY_CAPABILITIES";
    case IRP_MN_QUERY_RESOURCES:              return "QUERY_RESOURCES";
    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:  return "QUERY_RESOURCE_REQUIREMENTS";
    case IRP_MN_QUERY_DEVICE_TEXT:            return "QUERY_DEVICE_TEXT";
    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS: return "FILTER_RESOURCE_REQUIREMENTS";
    case IRP_MN_READ_CONFIG:                  return "READ_CONFIG";
    case IRP_MN_WRITE_CONFIG:                 return "WRITE_CONFIG";
    case IRP_MN_EJECT:                        return "EJECT";
    case IRP_MN_SET_LOCK:                     return "SET_LOCK";
    case IRP_MN_QUERY_ID:                     return "QUERY_ID";
    case IRP_MN_QUERY_PNP_DEVICE_STATE:       return "QUERY_PNP_DEVICE_STATE";
    case IRP_MN_QUERY_BUS_INFORMATION:        return "QUERY_BUS_INFORMATION";
    case IRP_MN_DEVICE_USAGE_NOTIFICATION:    return "DEVICE_USAGE_NOTIFICATION";
    case IRP_MN_SURPRISE_REMOVAL:             return "SURPRISE_REMOVAL";
    case IRP_MN_QUERY_LEGACY_BUS_INFORMATION: return "QUERY_LEGACY_BUS_INFORMATION";
//    case IRP_MN_BUS_RESET:                    return "BUS_RESET"
    default:                                  return "UNKNOWN";
  }
}

PCHAR STDCALL SystemControlMinorFunctionString(IN UCHAR MinorFunction) {
  switch (MinorFunction) {
    case IRP_MN_QUERY_ALL_DATA:         return "QUERY_ALL_DATA";
    case IRP_MN_QUERY_SINGLE_INSTANCE:  return "QUERY_SINGLE_INSTANCE";
    case IRP_MN_CHANGE_SINGLE_INSTANCE: return "CHANGE_SINGLE_INSTANCE";
    case IRP_MN_CHANGE_SINGLE_ITEM:     return "CHANGE_SINGLE_ITEM";
    case IRP_MN_ENABLE_EVENTS:          return "ENABLE_EVENTS";
    case IRP_MN_DISABLE_EVENTS:         return "DISABLE_EVENTS";
    case IRP_MN_ENABLE_COLLECTION:      return "ENABLE_COLLECTION";
    case IRP_MN_DISABLE_COLLECTION:     return "DISABLE_COLLECTION";
    case IRP_MN_REGINFO:                return "REGINFO";
    case IRP_MN_EXECUTE_METHOD:         return "EXECUTE_METHOD";
//    case IRP_MN_REGINFO_EX:             return "REGINFO_EX";
    default:                            return "UNKNOWN";
  }
}

PCHAR STDCALL PowerMinorFunctionString(IN UCHAR MinorFunction) {
  switch (MinorFunction) {
    case IRP_MN_WAIT_WAKE:      return "WAIT_WAKE";
    case IRP_MN_POWER_SEQUENCE: return "POWER_SEQUENCE";
    case IRP_MN_SET_POWER:      return "SET_POWER";
    case IRP_MN_QUERY_POWER:    return "QUERY_POWER";
    default:                    return "UNKNOWN";
  }
}

PCHAR STDCALL QueryDeviceRelationsString(IN DEVICE_RELATION_TYPE Type) {
  switch (Type) {
    case BusRelations:         return "BusRelations";
    case EjectionRelations:    return "EjectionRelations";
    case RemovalRelations:     return "RemovalRelations";
    case TargetDeviceRelation: return "TargetDeviceRelation";
    default:                   return "UnknownRelation";
  }
}

PCHAR STDCALL QueryIdString(IN BUS_QUERY_ID_TYPE IdType) {
  switch (IdType) {
    case BusQueryDeviceID:           return "BusQueryDeviceID";
    case BusQueryHardwareIDs:        return "BusQueryHardwareIDs";
    case BusQueryCompatibleIDs:      return "BusQueryCompatibleIDs";
    case BusQueryInstanceID:         return "BusQueryInstanceID";
    case BusQueryDeviceSerialNumber: return "BusQueryDeviceSerialNumber";
    default:                         return "BusQueryUnknown";
  }
}

PCHAR STDCALL SrbFunctionString(IN UCHAR Function) {
  switch (Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:       return "EXECUTE_SCSI";
    case SRB_FUNCTION_CLAIM_DEVICE:       return "CLAIM_DEVICE";
    case SRB_FUNCTION_IO_CONTROL:         return "IO_CONTROL";
    case SRB_FUNCTION_RECEIVE_EVENT:      return "RECEIVE_EVENT";
    case SRB_FUNCTION_RELEASE_QUEUE:      return "RELEASE_QUEUE";
    case SRB_FUNCTION_ATTACH_DEVICE:      return "ATTACH_DEVICE";
    case SRB_FUNCTION_RELEASE_DEVICE:     return "RELEASE_DEVICE";
    case SRB_FUNCTION_SHUTDOWN:           return "SHUTDOWN";
    case SRB_FUNCTION_FLUSH:              return "FLUSH";
    case SRB_FUNCTION_ABORT_COMMAND:      return "ABORT_COMMAND";
    case SRB_FUNCTION_RELEASE_RECOVERY:   return "RELEASE_RECOVERY";
    case SRB_FUNCTION_RESET_BUS:          return "RESET_BUS";
    case SRB_FUNCTION_RESET_DEVICE:       return "RESET_DEVICE";
    case SRB_FUNCTION_TERMINATE_IO:       return "TERMINATE_IO";
    case SRB_FUNCTION_FLUSH_QUEUE:        return "FLUSH_QUEUE";
    case SRB_FUNCTION_REMOVE_DEVICE:      return "REMOVE_DEVICE";
    case SRB_FUNCTION_WMI:                return "WMI";
    case SRB_FUNCTION_LOCK_QUEUE:         return "LOCK_QUEUE";
    case SRB_FUNCTION_UNLOCK_QUEUE:       return "UNLOCK_QUEUE";
//    case SRB_FUNCTION_RESET_LOGICAL_UNIT: return "RESET_LOGICAL_UNIT";
    default:                              return "SRB_FUNCTION_UNKNOWN";
  }
}

PCHAR STDCALL DeviceIoControlString(IN ULONG IoControlCode) {
  switch (IoControlCode) {
    case IOCTL_SCSI_GET_INQUIRY_DATA:           return "IOCTL_SCSI_GET_INQUIRY_DATA";
    case IOCTL_SCSI_GET_CAPABILITIES:           return "IOCTL_SCSI_GET_CAPABILITIES";
    case IOCTL_SCSI_GET_ADDRESS:                return "IOCTL_SCSI_GET_ADDRESS";
    case IOCTL_SCSI_MINIPORT:                   return "IOCTL_SCSI_MINIPORT";
    case IOCTL_SCSI_PASS_THROUGH:               return "IOCTL_SCSI_PASS_THROUGH";
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:        return "IOCTL_SCSI_PASS_THROUGH_DIRECT";
    case IOCTL_SCSI_RESCAN_BUS:                 return "IOCTL_SCSI_RESCAN_BUS";
    case IOCTL_DISK_CHECK_VERIFY:               return "IOCTL_DISK_CHECK_VERIFY";
    case IOCTL_DISK_CONTROLLER_NUMBER:          return "IOCTL_DISK_CONTROLLER_NUMBER";
//    case IOCTL_DISK_CREATE_DISK:                return "IOCTL_DISK_CREATE_DISK";
    case IOCTL_DISK_DELETE_DRIVE_LAYOUT:        return "IOCTL_DISK_DELETE_DRIVE_LAYOUT";
    case IOCTL_DISK_FIND_NEW_DEVICES:           return "IOCTL_DISK_FIND_NEW_DEVICES";
    case IOCTL_DISK_FORMAT_TRACKS:              return "IOCTL_DISK_FORMAT_TRACKS";
    case IOCTL_DISK_FORMAT_TRACKS_EX:           return "IOCTL_DISK_FORMAT_TRACKS_EX";
    case IOCTL_DISK_GET_CACHE_INFORMATION:      return "IOCTL_DISK_GET_CACHE_INFORMATION";
    case IOCTL_DISK_GET_DRIVE_GEOMETRY:         return "IOCTL_DISK_GET_DRIVE_GEOMETRY";
//    case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:      return "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX";
    case IOCTL_DISK_GET_DRIVE_LAYOUT:           return "IOCTL_DISK_GET_DRIVE_LAYOUT";
//    case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:        return "IOCTL_DISK_GET_DRIVE_LAYOUT_EX";
    case IOCTL_DISK_GET_MEDIA_TYPES:            return "IOCTL_DISK_GET_MEDIA_TYPES";
//    case IOCTL_DISK_GET_LENGTH_INFO:            return "IOCTL_DISK_GET_LENGTH_INFO";
    case IOCTL_DISK_GET_PARTITION_INFO:         return "IOCTL_DISK_GET_PARTITION_INFO";
//    case IOCTL_DISK_GET_PARTITION_INFO_EX:      return "IOCTL_DISK_GET_PARTITION_INFO_EX";
    case IOCTL_DISK_GROW_PARTITION:             return "IOCTL_DISK_GROW_PARTITION";
    case IOCTL_DISK_INTERNAL_CLEAR_VERIFY:      return "IOCTL_DISK_INTERNAL_CLEAR_VERIFY";
    case IOCTL_DISK_INTERNAL_SET_VERIFY:        return "IOCTL_DISK_INTERNAL_SET_VERIFY";
    case IOCTL_DISK_IS_WRITABLE:                return "IOCTL_DISK_IS_WRITABLE";
    case IOCTL_DISK_PERFORMANCE:                return "IOCTL_DISK_PERFORMANCE";
//    case IOCTL_DISK_PERFORMANCE_OFF:            return "IOCTL_DISK_PERFORMANCE_OFF";
    case IOCTL_DISK_REASSIGN_BLOCKS:            return "IOCTL_DISK_REASSIGN_BLOCKS";
    case IOCTL_DISK_RESERVE:                    return "IOCTL_DISK_RESERVE";
    case IOCTL_DISK_SET_CACHE_INFORMATION:      return "IOCTL_DISK_SET_CACHE_INFORMATION";
    case IOCTL_DISK_SET_DRIVE_LAYOUT:           return "IOCTL_DISK_SET_DRIVE_LAYOUT";
//    case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:        return "IOCTL_DISK_SET_DRIVE_LAYOUT_EX";
    case IOCTL_DISK_SET_PARTITION_INFO:         return "IOCTL_DISK_SET_PARTITION_INFO";
//    case IOCTL_DISK_SET_PARTITION_INFO_EX:      return "IOCTL_DISK_SET_PARTITION_INFO_EX";
    case IOCTL_DISK_VERIFY:                     return "IOCTL_DISK_VERIFY";
    case SMART_GET_VERSION:                     return "SMART_GET_VERSION";
    case SMART_RCV_DRIVE_DATA:                  return "SMART_RCV_DRIVE_DATA";
    case SMART_SEND_DRIVE_COMMAND:              return "SMART_SEND_DRIVE_COMMAND";
    case IOCTL_STORAGE_CHECK_VERIFY:            return "IOCTL_STORAGE_CHECK_VERIFY";
    case IOCTL_STORAGE_CHECK_VERIFY2:           return "IOCTL_STORAGE_CHECK_VERIFY2";
    case IOCTL_STORAGE_EJECT_MEDIA:             return "IOCTL_STORAGE_EJECT_MEDIA";
    case IOCTL_STORAGE_EJECTION_CONTROL:        return "IOCTL_STORAGE_EJECTION_CONTROL";
    case IOCTL_STORAGE_FIND_NEW_DEVICES:        return "IOCTL_STORAGE_FIND_NEW_DEVICES";
    case IOCTL_STORAGE_GET_DEVICE_NUMBER:       return "IOCTL_STORAGE_GET_DEVICE_NUMBER";
//    case IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER: return "IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER";
    case IOCTL_STORAGE_GET_MEDIA_TYPES:         return "IOCTL_STORAGE_GET_MEDIA_TYPES";
    case IOCTL_STORAGE_GET_MEDIA_TYPES_EX:      return "IOCTL_STORAGE_GET_MEDIA_TYPES_EX";
    case IOCTL_STORAGE_LOAD_MEDIA:              return "IOCTL_STORAGE_LOAD_MEDIA";
    case IOCTL_STORAGE_LOAD_MEDIA2:             return "IOCTL_STORAGE_LOAD_MEDIA2";
    case IOCTL_STORAGE_MCN_CONTROL:             return "IOCTL_STORAGE_MCN_CONTROL";
    case IOCTL_STORAGE_MEDIA_REMOVAL:           return "IOCTL_STORAGE_MEDIA_REMOVAL";
    case IOCTL_STORAGE_PREDICT_FAILURE:         return "IOCTL_STORAGE_PREDICT_FAILURE";
    case IOCTL_STORAGE_QUERY_PROPERTY:          return "IOCTL_STORAGE_QUERY_PROPERTY";
    case IOCTL_STORAGE_RELEASE:                 return "IOCTL_STORAGE_RELEASE";
    case IOCTL_STORAGE_RESERVE:                 return "IOCTL_STORAGE_RESERVE";
    case IOCTL_STORAGE_RESET_BUS:               return "IOCTL_STORAGE_RESET_BUS";
    case IOCTL_STORAGE_RESET_DEVICE:            return "IOCTL_STORAGE_RESET_DEVICE";
    case IOCTL_AOE_SCAN:                        return "IOCTL_AOE_SCAN";
    case IOCTL_AOE_SHOW:                        return "IOCTL_AOE_SHOW";
    case IOCTL_AOE_MOUNT:                       return "IOCTL_AOE_MOUNT";
    case IOCTL_AOE_UMOUNT:                      return "IOCTL_AOE_UMOUNT";
    default:                                    return "IOCTL_UNKNOWN";
  }
}

PCHAR STDCALL DeviceTextTypeString(IN DEVICE_TEXT_TYPE DeviceTextType) {
  switch (DeviceTextType) {
    case DeviceTextDescription:         return "DeviceTextDescription";
    case DeviceTextLocationInformation: return "DeviceTextLocationInformation";
    default:                            return "DeviceTextUnknown";
  }
}

PCHAR STDCALL SCSIOPString(IN UCHAR OperationCode) {
  switch (OperationCode) {
    case SCSIOP_TEST_UNIT_READY: return "TEST_UNIT_READY";
    case SCSIOP_READ:            return "READ";
    case SCSIOP_WRITE:           return "WRITE";
    case SCSIOP_VERIFY:          return "VERIFY";
    case SCSIOP_READ_CAPACITY:   return "READ_CAPACITY";
    case SCSIOP_MODE_SENSE:      return "MODE_SENSE";
    case SCSIOP_MEDIUM_REMOVAL:  return "MEDIUM_REMOVAL";
    case SCSIOP_READ16:          return "READ16";
    case SCSIOP_WRITE16:         return "WRITE16";
    case SCSIOP_VERIFY16:        return "VERIFY16";
    case SCSIOP_READ_CAPACITY16: return "CAPACITY16";
    default:                     return "SCSIOP_UNKNOWN";
  }
}
