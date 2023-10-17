#pragma once

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#endif

#define GENERATE_IOCTL(code) CTL_CODE(FILE_DEVICE_UNKNOWN, (1 << 11) | code, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_PROTECT_REQUEST GENERATE_IOCTL(0x123)
typedef struct KProtectRequest
{
    ULONG pid;
    NTSTATUS result;
} KProtectRequest;

#if 0

typedef struct _KAFFINITY_EX
{
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    ULONGLONG Bitmap[20];                                                   //0x8
} KAFFINITY_EX, * PKAFFINITY_EX;

typedef union _KEXECUTE_OPTIONS
{
    UCHAR ExecuteDisable : 1;                                               //0x0
    UCHAR ExecuteEnable : 1;                                                //0x0
    UCHAR DisableThunkEmulation : 1;                                        //0x0
    UCHAR Permanent : 1;                                                    //0x0
    UCHAR ExecuteDispatchEnable : 1;                                        //0x0
    UCHAR ImageDispatchEnable : 1;                                          //0x0
    UCHAR DisableExceptionChainValidation : 1;                              //0x0
    UCHAR Spare : 1;                                                        //0x0
    volatile UCHAR ExecuteOptions;                                          //0x0
    UCHAR ExecuteOptionsNV;                                                 //0x0
} KEXECUTE_OPTIONS, * PKEXECUTE_OPTIONS;

typedef union _KSTACK_COUNT
{
    LONG Value;                                                             //0x0
    ULONG State : 3;                                                        //0x0
    ULONG StackCount : 29;                                                  //0x0
} KSTACK_COUNT, *PKSTACK_COUNT;

typedef struct _RTL_RB_TREE
{
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
    union
    {
        UCHAR Encoded : 1;                                                  //0x8
        struct _RTL_BALANCED_NODE* Min;                                     //0x8
    };
} RTL_RB_TREE, * PRTL_RB_TREE;

typedef struct _KLOCK_ENTRY_LOCK_STATE
{
    union
    {
        struct
        {
            ULONGLONG CrossThreadReleasable : 1;                              //0x0
            ULONGLONG Busy : 1;                                               //0x0
            ULONGLONG Reserved : 61;                                          //0x0
            ULONGLONG InTree : 1;                                             //0x0
        };
        PVOID LockState;                                                    //0x0
    };
    union
    {
        PVOID SessionState;                                                 //0x8
        struct
        {
            ULONG SessionId;                                                //0x8
            ULONG SessionPad;                                               //0xc
        };
    };
} KLOCK_ENTRY_LOCK_STATE, * PKLOCK_ENTRY_LOCK_STATE;

typedef union _KLOCK_ENTRY_BOOST_BITMAP
{
    ULONG AllFields;                                                        //0x0
    ULONG AllBoosts : 17;                                                     //0x0
    ULONG Reserved : 15;                                                      //0x0
    USHORT CpuBoostsBitmap : 15;                                              //0x0
    struct
    {
        USHORT IoBoost : 1;                                                   //0x0
        USHORT IoQoSBoost : 1;                                                    //0x2
        USHORT IoNormalPriorityWaiterCount : 8;                                   //0x2
    };
    USHORT IoQoSWaiterCount : 7;                                              //0x2
} KLOCK_ENTRY_BOOST_BITMAP, * PKLOCK_ENTRY_BOOST_BITMAP;

typedef struct _KLOCK_ENTRY
{
    union
    {
        RTL_BALANCED_NODE TreeNode;                                 //0x0
        SINGLE_LIST_ENTRY FreeListEntry;                            //0x0
    };
    union
    {
        ULONG EntryFlags;                                                   //0x18
        struct
        {
            UCHAR EntryOffset;                                              //0x18
            union
            {
                UCHAR ThreadLocalFlags;                                     //0x19
                struct
                {
                    UCHAR WaitingBit : 1;                                     //0x19
                    UCHAR Spare0 : 7;                                         //0x19
                };
            };
            union
            {
                UCHAR AcquiredByte;                                         //0x1a
                UCHAR AcquiredBit : 1;                                        //0x1a
            };
            union
            {
                UCHAR CrossThreadFlags;                                     //0x1b
                struct
                {
                    UCHAR HeadNodeBit : 1;                                    //0x1b
                    UCHAR IoPriorityBit : 1;                                  //0x1b
                    UCHAR IoQoSWaiter : 1;                                    //0x1b
                    UCHAR Spare1 : 5;                                         //0x1b
                };
            };
        };
        struct
        {
            ULONG StaticState : 8;                                            //0x18
            ULONG AllFlags : 24;                                              //0x18
        };
    };
    ULONG SpareFlags;                                                       //0x1c
    union
    {
        KLOCK_ENTRY_LOCK_STATE LockState;                           //0x20
        PVOID volatile LockUnsafe;                                          //0x20
        struct
        {
            volatile UCHAR CrossThreadReleasableAndBusyByte;                //0x20
            UCHAR Reserved[6];                                              //0x21
            volatile UCHAR InTreeByte;                                      //0x27
            union
            {
                PVOID SessionState;                                         //0x28
                struct
                {
                    ULONG SessionId;                                        //0x28
                    ULONG SessionPad;                                       //0x2c
                };
            };
        };
    };
    union
    {
        struct
        {
            RTL_RB_TREE OwnerTree;                                  //0x30
            RTL_RB_TREE WaiterTree;                                 //0x40
        };
        CHAR CpuPriorityKey;                                                //0x30
    };
    ULONGLONG EntryLock;                                                    //0x50
    KLOCK_ENTRY_BOOST_BITMAP BoostBitmap;                            //0x58
    ULONG SparePad;                                                         //0x5c
} KLOCK_ENTRY, * PKLOCK_ENTRY;

typedef struct _KSCB
{
    ULONGLONG GenerationCycles;                                             //0x0
    ULONGLONG MinQuotaCycleTarget;                                          //0x8
    ULONGLONG MaxQuotaCycleTarget;                                          //0x10
    ULONGLONG RankCycleTarget;                                              //0x18
    ULONGLONG LongTermCycles;                                               //0x20
    ULONGLONG LastReportedCycles;                                           //0x28
    volatile ULONGLONG OverQuotaHistory;                                    //0x30
    ULONGLONG ReadyTime;                                                    //0x38
    ULONGLONG InsertTime;                                                   //0x40
    LIST_ENTRY PerProcessorList;                                    //0x48
    RTL_BALANCED_NODE QueueNode;                                    //0x58
    UCHAR Inserted : 1;                                                     //0x70
    UCHAR MaxOverQuota : 1;                                                 //0x70
    UCHAR MinOverQuota : 1;                                                 //0x70
    UCHAR RankBias : 1;                                                     //0x70
    UCHAR SoftCap : 1;                                                      //0x70
    UCHAR ShareRankOwner : 1;                                               //0x70
    UCHAR Spare1 : 2;                                                       //0x70
    UCHAR Depth;                                                            //0x71
    USHORT ReadySummary;                                                    //0x72
    ULONG Rank;                                                             //0x74
    volatile ULONG* ShareRank;                                              //0x78
    volatile ULONG OwnerShareRank;                                          //0x80
    LIST_ENTRY ReadyListHead[16];                                           //0x88
    RTL_RB_TREE ChildScbQueue;                                              //0x188
    struct _KSCB* Parent;                                                   //0x198
    struct _KSCB* Root;                                                     //0x1a0
} KSCB, * PKSCB;

typedef struct _KSCHEDULING_GROUP_POLICY
{
    union
    {
        ULONG Value;                                                        //0x0
        USHORT Weight;                                                      //0x0
        struct
        {
            USHORT MinRate;                                                 //0x0
            USHORT MaxRate;                                                 //0x2
        };
    };
    union
    {
        ULONG AllFlags;                                                     //0x4
        struct
        {
            ULONG Type : 1;                                                 //0x4
            ULONG Disabled : 1;                                             //0x4
            ULONG RankBias : 1;                                             //0x4
            ULONG Spare1 : 29;                                              //0x4
        };
    };
} KSCHEDULING_GROUP_POLICY, * PKSCHEDULING_GROUP_POLICY;

typedef struct _KSCHEDULING_GROUP
{
    KSCHEDULING_GROUP_POLICY Policy;                                        //0x0
    ULONG RelativeWeight;                                                   //0x8
    ULONG ChildMinRate;                                                     //0xc
    ULONG ChildMinWeight;                                                   //0x10
    ULONG ChildTotalWeight;                                                 //0x14
    ULONGLONG QueryHistoryTimeStamp;                                        //0x18
    LONGLONG NotificationCycles;                                            //0x20
    LONGLONG MaxQuotaLimitCycles;                                           //0x28
    volatile LONGLONG MaxQuotaCyclesRemaining;                              //0x30
    union
    {
        LIST_ENTRY SchedulingGroupList;                                     //0x38
        LIST_ENTRY Sibling;                                                 //0x38
    };
    KDPC* NotificationDpc;                                                  //0x48
    LIST_ENTRY ChildList;                                                   //0x50
    struct _KSCHEDULING_GROUP* Parent;                                      //0x60
    KSCB PerProcessor[1];                                                   //0x80
} KSCHEDULING_GROUP, * PKSCHEDULING_GROUP;

typedef struct _KPROCESS_REAL
{
    DISPATCHER_HEADER Header;                                               //0x0
    LIST_ENTRY ProfileListHead;                                             //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    LIST_ENTRY ThreadListHead;                                              //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    KAFFINITY_EX Affinity;                                                  //0x50
    ULONGLONG AffinityPadding[12];                                          //0xf8
    LIST_ENTRY ReadyListHead;                                               //0x158
    SINGLE_LIST_ENTRY SwapListEntry;                                        //0x168
    volatile KAFFINITY_EX ActiveProcessors;                                 //0x170
    ULONGLONG ActiveProcessorsPadding[12];                                  //0x218
    union
    {
        struct
        {
            ULONG AutoAlignment : 1;                                        //0x278
            ULONG DisableBoost : 1;                                         //0x278
            ULONG DisableQuantum : 1;                                       //0x278
            ULONG DeepFreeze : 1;                                           //0x278
            ULONG TimerVirtualization : 1;                                  //0x278
            ULONG CheckStackExtents : 1;                                    //0x278
            ULONG CacheIsolationEnabled : 1;                                //0x278
            ULONG PpmPolicy : 3;                                            //0x278
            ULONG VaSpaceDeleted : 1;                                       //0x278
            ULONG ReservedFlags : 21;                                       //0x278
        };
        volatile LONG ProcessFlags;                                         //0x278
    };
    ULONG ActiveGroupsMask;                                                 //0x27c
    CHAR BasePriority;                                                      //0x280
    CHAR QuantumReset;                                                      //0x281
    CHAR Visited;                                                           //0x282
    KEXECUTE_OPTIONS Flags;                                                 //0x283
    USHORT ThreadSeed[20];                                                  //0x284
    USHORT ThreadSeedPadding[12];                                           //0x2ac
    USHORT IdealProcessor[20];                                              //0x2c4
    USHORT IdealProcessorPadding[12];                                       //0x2ec
    USHORT IdealNode[20];                                                   //0x304
    USHORT IdealNodePadding[12];                                            //0x32c
    USHORT IdealGlobalNode;                                                 //0x344
    USHORT Spare1;                                                          //0x346
    volatile KSTACK_COUNT StackCount;                                       //0x348
    LIST_ENTRY ProcessListEntry;                                            //0x350
    ULONGLONG CycleTime;                                                    //0x360
    ULONGLONG ContextSwitches;                                              //0x368
    KSCHEDULING_GROUP* SchedulingGroup;                                     //0x370
    ULONG FreezeCount;                                                      //0x378
    ULONG KernelTime;                                                       //0x37c
    ULONG UserTime;                                                         //0x380
    ULONG ReadyTime;                                                        //0x384
    ULONGLONG UserDirectoryTableBase;                                       //0x388
    UCHAR AddressPolicy;                                                    //0x390
    UCHAR Spare2[71];                                                       //0x391
    PVOID InstrumentationCallback;                                          //0x3d8
    union
    {
        ULONGLONG SecureHandle;                                             //0x3e0
        struct
        {
            ULONGLONG SecureProcess : 1;                                    //0x3e0
            ULONGLONG Unused : 1;                                           //0x3e0
        } Flags;                                                            //0x3e0
    } SecureState;                                                          //0x3e0
    ULONGLONG KernelWaitTime;                                               //0x3e8
    ULONGLONG UserWaitTime;                                                 //0x3f0
    ULONGLONG EndPadding[8];                                                //0x3f8
} KPROCESS_REAL, * PKPROCESS_REAL;

#ifdef EX_PUSH_LOCK
#undef EX_PUSH_LOCK
#undef PEX_PUSH_LOCK
#endif

typedef struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        PVOID Ptr;                                                          //0x0
    };
} EX_PUSH_LOCK, * PEX_PUSH_LOCK;

typedef struct _EX_FAST_REF
{
    union
    {
        PVOID Object;                                                       //0x0
        ULONGLONG RefCnt : 4;                                                 //0x0
        ULONGLONG Value;                                                    //0x0
    };
} EX_FAST_REF, * PEX_FAST_REF;

typedef struct _COUNTER_READING
{
    HARDWARE_COUNTER_TYPE Type;                                       //0x0
    ULONG Index;                                                            //0x4
    ULONGLONG Start;                                                        //0x8
    ULONGLONG Total;                                                        //0x10
} COUNTER_READING, * PCOUNTER_READING;

typedef struct _THREAD_PERFORMANCE_DATA
{
    USHORT Size;                                                            //0x0
    USHORT Version;                                                         //0x2
    PROCESSOR_NUMBER ProcessorNumber;                               //0x4
    ULONG ContextSwitches;                                                  //0x8
    ULONG HwCountersCount;                                                  //0xc
    volatile ULONGLONG UpdateCount;                                         //0x10
    ULONGLONG WaitReasonBitMap;                                             //0x18
    ULONGLONG HardwareCounters;                                             //0x20
    COUNTER_READING CycleTime;                                      //0x28
    COUNTER_READING HwCounters[16];                                 //0x40
} THREAD_PERFORMANCE_DATA, * PTHREAD_PERFORMANCE_DATA;

typedef struct _KTHREAD_COUNTERS
{
    ULONGLONG WaitReasonBitMap;                                             //0x0
    PTHREAD_PERFORMANCE_DATA UserData;                              //0x8
    ULONG Flags;                                                            //0x10
    ULONG ContextSwitches;                                                  //0x14
    ULONGLONG CycleTimeBias;                                                //0x18
    ULONGLONG HardwareCounters;                                             //0x20
    COUNTER_READING HwCounter[16];                                  //0x28
} KTHREAD_COUNTERS, * PKTHREAD_COUNTERS;

typedef struct _RTL_UMS_CONTEXT
{
    SINGLE_LIST_ENTRY Link;                                         //0x0
    CONTEXT Context;                                                //0x10
    PVOID Teb;                                                              //0x4e0
    PVOID UserContext;                                                      //0x4e8
    union
    {
        struct
        {
            volatile ULONG ScheduledThread : 1;                               //0x4f0
            volatile ULONG Suspended : 1;                                     //0x4f0
            volatile ULONG VolatileContext : 1;                               //0x4f0
            volatile ULONG Terminated : 1;                                    //0x4f0
            volatile ULONG DebugActive : 1;                                   //0x4f0
            volatile ULONG RunningOnSelfThread : 1;                           //0x4f0
            volatile ULONG DenyRunningOnSelfThread : 1;                       //0x4f0
        };
        volatile LONG Flags;                                                //0x4f0
    };
    union
    {
        struct
        {
            volatile ULONGLONG KernelUpdateLock : 2;                          //0x4f8
            volatile ULONGLONG PrimaryClientID : 62;                          //0x4f8
        };
        volatile ULONGLONG ContextLock;                                     //0x4f8
    };
    struct _RTL_UMS_CONTEXT* PrimaryUmsContext;                             //0x500
    ULONG SwitchCount;                                                      //0x508
    ULONG KernelYieldCount;                                                 //0x50c
    ULONG MixedYieldCount;                                                  //0x510
    ULONG YieldCount;                                                       //0x514
} RTL_UMS_CONTEXT, * PRTL_UMS_CONTEXT;

typedef struct _UMS_CONTROL_BLOCK
{
    PRTL_UMS_CONTEXT UmsContext;                                    //0x0
    PSINGLE_LIST_ENTRY CompletionListEntry;                         //0x8
    PKEVENT CompletionListEvent;                                    //0x10
    ULONG ServiceSequenceNumber;                                            //0x18
    union
    {
        struct
        {
            KQUEUE UmsQueue;                                        //0x20
            LIST_ENTRY QueueEntry;                                  //0x60
            PRTL_UMS_CONTEXT YieldingUmsContext;                    //0x70
            PVOID YieldingParam;                                            //0x78
            PVOID UmsTeb;                                                   //0x80
        };
        struct
        {
            PKQUEUE UmsAssociatedQueue;                             //0x20
            PLIST_ENTRY UmsQueueListEntry;                          //0x28
            KEVENT UmsWaitEvent;                                    //0x30
            PVOID StagingArea;                                              //0x48
            union
            {
                struct
                {
                    ULONG UmsPrimaryDeliveredContext : 1;                     //0x50
                    ULONG UmsAssociatedQueueUsed : 1;                         //0x50
                    ULONG UmsThreadParked : 1;                                //0x50
                };
                ULONG UmsFlags;                                             //0x50
            };
        };
    };
} UMS_CONTROL_BLOCK, * PUMS_CONTROL_BLOCK;

typedef union _KWAIT_STATUS_REGISTER
{
    UCHAR Flags;                                                            //0x0
    UCHAR State : 3;                                                          //0x0
    UCHAR Affinity : 1;                                                       //0x0
    UCHAR Priority : 1;                                                       //0x0
    UCHAR Apc : 1;                                                            //0x0
    UCHAR UserApc : 1;                                                        //0x0
    UCHAR Alert : 1;                                                          //0x0
} KWAIT_STATUS_REGISTER, * PKWAIT_STATUS_REGISTER;

typedef struct _KTHREAD_REAL
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    PVOID SListFaultAddress;                                                //0x18
    ULONGLONG QuantumTarget;                                                //0x20
    PVOID InitialStack;                                                     //0x28
    PVOID volatile StackLimit;                                              //0x30
    PVOID StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    volatile ULONGLONG CycleTime;                                           //0x48
    ULONG CurrentRunTime;                                                   //0x50
    ULONG ExpectedRunTime;                                                  //0x54
    PVOID KernelStack;                                                      //0x58
    PXSAVE_FORMAT StateSaveArea;                                    //0x60
    PKSCHEDULING_GROUP volatile SchedulingGroup;                    //0x68
    union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x70
    volatile UCHAR Running;                                                 //0x71
    UCHAR Alerted[2];                                                       //0x72
    union
    {
        struct
        {
            ULONG AutoBoostActive : 1;                                        //0x74
            ULONG ReadyTransition : 1;                                        //0x74
            ULONG WaitNext : 1;                                               //0x74
            ULONG SystemAffinityActive : 1;                                   //0x74
            ULONG Alertable : 1;                                              //0x74
            ULONG UserStackWalkActive : 1;                                    //0x74
            ULONG ApcInterruptRequest : 1;                                    //0x74
            ULONG QuantumEndMigrate : 1;                                      //0x74
            ULONG UmsDirectedSwitchEnable : 1;                                //0x74
            ULONG TimerActive : 1;                                            //0x74
            ULONG SystemThread : 1;                                           //0x74
            ULONG ProcessDetachActive : 1;                                    //0x74
            ULONG CalloutActive : 1;                                          //0x74
            ULONG ScbReadyQueue : 1;                                          //0x74
            ULONG ApcQueueable : 1;                                           //0x74
            ULONG ReservedStackInUse : 1;                                     //0x74
            ULONG UmsPerformingSyscall : 1;                                   //0x74
            ULONG TimerSuspended : 1;                                         //0x74
            ULONG SuspendedWaitMode : 1;                                      //0x74
            ULONG SuspendSchedulerApcWait : 1;                                //0x74
            ULONG CetUserShadowStack : 1;                                     //0x74
            ULONG BypassProcessFreeze : 1;                                    //0x74
            ULONG Reserved : 10;                                              //0x74
        };
        LONG MiscFlags;                                                     //0x74
    };
    union
    {
        struct
        {
            ULONG ThreadFlagsSpare : 2;                                       //0x78
            ULONG AutoAlignment : 1;                                          //0x78
            ULONG DisableBoost : 1;                                           //0x78
            ULONG AlertedByThreadId : 1;                                      //0x78
            ULONG QuantumDonation : 1;                                        //0x78
            ULONG EnableStackSwap : 1;                                        //0x78
            ULONG GuiThread : 1;                                              //0x78
            ULONG DisableQuantum : 1;                                         //0x78
            ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
            ULONG DeferPreemption : 1;                                        //0x78
            ULONG QueueDeferPreemption : 1;                                   //0x78
            ULONG ForceDeferSchedule : 1;                                     //0x78
            ULONG SharedReadyQueueAffinity : 1;                               //0x78
            ULONG FreezeCount : 1;                                            //0x78
            ULONG TerminationApcRequest : 1;                                  //0x78
            ULONG AutoBoostEntriesExhausted : 1;                              //0x78
            ULONG KernelStackResident : 1;                                    //0x78
            ULONG TerminateRequestReason : 2;                                 //0x78
            ULONG ProcessStackCountDecremented : 1;                           //0x78
            ULONG RestrictedGuiThread : 1;                                    //0x78
            ULONG VpBackingThread : 1;                                        //0x78
            ULONG ThreadFlagsSpare2 : 1;                                      //0x78
            ULONG EtwStackTraceApcInserted : 8;                               //0x78
        };
        volatile LONG ThreadFlags;                                          //0x78
    };
    volatile UCHAR Tag;                                                     //0x7c
    UCHAR SystemHeteroCpuPolicy;                                            //0x7d
    UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
    union
    {
        struct
        {
            UCHAR RunningNonRetpolineCode : 1;                                //0x7f
            UCHAR SpecCtrlSpare : 7;                                          //0x7f
        };
        UCHAR SpecCtrl;                                                     //0x7f
    };
    ULONG SystemCallNumber;                                                 //0x80
    ULONG ReadyTime;                                                        //0x84
    PVOID FirstArgument;                                                    //0x88
    PKTRAP_FRAME TrapFrame;                                         //0x90
    union
    {
        KAPC_STATE ApcState;                                        //0x98
        struct
        {
            UCHAR ApcStateFill[43];                                         //0x98
            CHAR Priority;                                                  //0xc3
            ULONG UserIdealProcessor;                                       //0xc4
        };
    };
    volatile LONGLONG WaitStatus;                                           //0xc8
    PKWAIT_BLOCK WaitBlockList;                                     //0xd0
    union
    {
        LIST_ENTRY WaitListEntry;                                   //0xd8
        SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
    };
    DISPATCHER_HEADER* volatile Queue;                              //0xe8
    PVOID Teb;                                                              //0xf0
    ULONGLONG RelativeTimerBias;                                            //0xf8
    KTIMER Timer;                                                   //0x100
    union
    {
        KWAIT_BLOCK WaitBlock[4];                                   //0x140
        struct
        {
            UCHAR WaitBlockFill4[20];                                       //0x140
            ULONG ContextSwitches;                                          //0x154
        };
        struct
        {
            UCHAR WaitBlockFill5[68];                                       //0x140
            volatile UCHAR State;                                           //0x184
            CHAR Spare13;                                                   //0x185
            UCHAR WaitIrql;                                                 //0x186
            CHAR WaitMode;                                                  //0x187
        };
        struct
        {
            UCHAR WaitBlockFill6[116];                                      //0x140
            ULONG WaitTime;                                                 //0x1b4
        };
        struct
        {
            UCHAR WaitBlockFill7[164];                                      //0x140
            union
            {
                struct
                {
                    SHORT KernelApcDisable;                                 //0x1e4
                    SHORT SpecialApcDisable;                                //0x1e6
                };
                ULONG CombinedApcDisable;                                   //0x1e4
            };
        };
        struct
        {
            UCHAR WaitBlockFill8[40];                                       //0x140
            PKTHREAD_COUNTERS ThreadCounters;                       //0x168
        };
        struct
        {
            UCHAR WaitBlockFill9[88];                                       //0x140
            PXSTATE_SAVE XStateSave;                                //0x198
        };
        struct
        {
            UCHAR WaitBlockFill10[136];                                     //0x140
            PVOID volatile Win32Thread;                                     //0x1c8
        };
        struct
        {
            UCHAR WaitBlockFill11[176];                                     //0x140
            PUMS_CONTROL_BLOCK Ucb;                                 //0x1f0
            KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
        };
    };
    union
    {
        volatile LONG ThreadFlags2;                                         //0x200
        struct
        {
            ULONG BamQosLevel : 8;                                            //0x200
            ULONG ThreadFlags2Reserved : 24;                                  //0x200
        };
    };
    ULONG Spare21;                                                          //0x204
    LIST_ENTRY QueueListEntry;                                      //0x208
    union
    {
        volatile ULONG NextProcessor;                                       //0x218
        struct
        {
            ULONG NextProcessorNumber : 31;                                   //0x218
            ULONG SharedReadyQueue : 1;                                       //0x218
        };
    };
    LONG QueuePriority;                                                     //0x21c
    struct _KPROCESS_REAL* Process;                                              //0x220
    union
    {
        GROUP_AFFINITY UserAffinity;                                //0x228
        struct
        {
            UCHAR UserAffinityFill[10];                                     //0x228
            CHAR PreviousMode;                                              //0x232
            CHAR BasePriority;                                              //0x233
            union
            {
                CHAR PriorityDecrement;                                     //0x234
                struct
                {
                    UCHAR ForegroundBoost : 4;                                //0x234
                    UCHAR UnusualBoost : 4;                                   //0x234
                };
            };
            UCHAR Preempted;                                                //0x235
            UCHAR AdjustReason;                                             //0x236
            CHAR AdjustIncrement;                                           //0x237
        };
    };
    ULONGLONG AffinityVersion;                                              //0x238
    union
    {
        GROUP_AFFINITY Affinity;                                    //0x240
        struct
        {
            UCHAR AffinityFill[10];                                         //0x240
            UCHAR ApcStateIndex;                                            //0x24a
            UCHAR WaitBlockCount;                                           //0x24b
            ULONG IdealProcessor;                                           //0x24c
        };
    };
    ULONGLONG NpxState;                                                     //0x250
    union
    {
        KAPC_STATE SavedApcState;                                   //0x258
        struct
        {
            UCHAR SavedApcStateFill[43];                                    //0x258
            UCHAR WaitReason;                                               //0x283
            CHAR SuspendCount;                                              //0x284
            CHAR Saturation;                                                //0x285
            USHORT SListFaultCount;                                         //0x286
        };
    };
    union
    {
        KAPC SchedulerApc;                                          //0x288
        struct
        {
            UCHAR SchedulerApcFill0[1];                                     //0x288
            UCHAR ResourceIndex;                                            //0x289
        };
        struct
        {
            UCHAR SchedulerApcFill1[3];                                     //0x288
            UCHAR QuantumReset;                                             //0x28b
        };
        struct
        {
            UCHAR SchedulerApcFill2[4];                                     //0x288
            ULONG KernelTime;                                               //0x28c
        };
        struct
        {
            UCHAR SchedulerApcFill3[64];                                    //0x288
            struct _KPRCB* volatile WaitPrcb;                               //0x2c8
        };
        struct
        {
            UCHAR SchedulerApcFill4[72];                                    //0x288
            PVOID LegoData;                                                 //0x2d0
        };
        struct
        {
            UCHAR SchedulerApcFill5[83];                                    //0x288
            UCHAR CallbackNestingLevel;                                     //0x2db
            ULONG UserTime;                                                 //0x2dc
        };
    };
    KEVENT SuspendEvent;                                            //0x2e0
    LIST_ENTRY ThreadListEntry;                                     //0x2f8
    LIST_ENTRY MutantListHead;                                      //0x308
    UCHAR AbEntrySummary;                                                   //0x318
    UCHAR AbWaitEntryCount;                                                 //0x319
    UCHAR AbAllocationRegionCount;                                          //0x31a
    CHAR SystemPriority;                                                    //0x31b
    ULONG SecureThreadCookie;                                               //0x31c
    PKLOCK_ENTRY LockEntries;                                       //0x320
    SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x328
    SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x330
    UCHAR PriorityFloorCounts[16];                                          //0x338
    UCHAR PriorityFloorCountsReserved[16];                                  //0x348
    ULONG PriorityFloorSummary;                                             //0x358
    volatile LONG AbCompletedIoBoostCount;                                  //0x35c
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x360
    volatile SHORT KeReferenceCount;                                        //0x364
    UCHAR AbOrphanedEntrySummary;                                           //0x366
    UCHAR AbOwnedEntryCount;                                                //0x367
    ULONG ForegroundLossTime;                                               //0x368
    union
    {
        LIST_ENTRY GlobalForegroundListEntry;                       //0x370
        struct
        {
            SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x370
            ULONGLONG InGlobalForegroundList;                               //0x378
        };
    };
    LONGLONG ReadOperationCount;                                            //0x380
    LONGLONG WriteOperationCount;                                           //0x388
    LONGLONG OtherOperationCount;                                           //0x390
    LONGLONG ReadTransferCount;                                             //0x398
    LONGLONG WriteTransferCount;                                            //0x3a0
    LONGLONG OtherTransferCount;                                            //0x3a8
    PKSCB QueuedScb;                                                //0x3b0
    volatile ULONG ThreadTimerDelay;                                        //0x3b8
    union
    {
        volatile LONG ThreadFlags3;                                         //0x3bc
        struct
        {
            ULONG ThreadFlags3Reserved : 8;                                   //0x3bc
            ULONG PpmPolicy : 2;                                              //0x3bc
            ULONG ThreadFlags3Reserved2 : 22;                                 //0x3bc
        };
    };
    ULONGLONG TracingPrivate[1];                                            //0x3c0
    PVOID SchedulerAssist;                                                  //0x3c8
    PVOID volatile AbWaitObject;                                            //0x3d0
    ULONG ReservedPreviousReadyTimeValue;                                   //0x3d8
    ULONGLONG KernelWaitTime;                                               //0x3e0
    ULONGLONG UserWaitTime;                                                 //0x3e8
    union
    {
        LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
        struct
        {
            SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
            ULONGLONG InGlobalUpdateVpThreadPriorityList;                   //0x3f8
        };
    };
    LONG SchedulerAssistPriorityFloor;                                      //0x400
    ULONG Spare28;                                                          //0x404
    ULONGLONG EndPadding[5];                                                //0x408
} KTHREAD_REAL, * PKTHREAD_REAL;

typedef union _PS_CLIENT_SECURITY_CONTEXT
{
    ULONGLONG ImpersonationData;                                            //0x0
    PVOID ImpersonationToken;                                               //0x0
    ULONGLONG ImpersonationLevel : 2;                                         //0x0
    ULONGLONG EffectiveOnly : 1;                                              //0x0
} PS_CLIENT_SECURITY_CONTEXT, * PPS_CLIENT_SECURITY_CONTEXT;

typedef struct _PS_PROPERTY_SET
{
    struct _LIST_ENTRY ListHead;                                            //0x0
    ULONGLONG Lock;                                                         //0x10
} PS_PROPERTY_SET, * PPS_PROPERTY_SET;

typedef struct _ETHREAD_REAL
{
    KTHREAD_REAL Tcb;                                                    //0x0
    LARGE_INTEGER CreateTime;                                        //0x430
    union
    {
        LARGE_INTEGER ExitTime;                                      //0x438
        LIST_ENTRY KeyedWaitChain;                                  //0x438
    };
    union
    {
        LIST_ENTRY PostBlockList;                                   //0x448
        struct
        {
            PVOID ForwardLinkShadow;                                        //0x448
            PVOID StartAddress;                                             //0x450
        };
    };
    union
    {
        struct _TERMINATION_PORT* TerminationPort;                          //0x458
        struct _ETHREAD* ReaperLink;                                        //0x458
        PVOID KeyedWaitValue;                                               //0x458
    };
    ULONGLONG ActiveTimerListLock;                                          //0x460
    LIST_ENTRY ActiveTimerListHead;                                 //0x468
    CLIENT_ID Cid;                                                  //0x478
    union
    {
        KSEMAPHORE KeyedWaitSemaphore;                              //0x488
        KSEMAPHORE AlpcWaitSemaphore;                               //0x488
    };
    PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                       //0x4a8
    LIST_ENTRY IrpList;                                             //0x4b0
    ULONGLONG TopLevelIrp;                                                  //0x4c0
    DEVICE_OBJECT* DeviceToVerify;                                  //0x4c8
    PVOID Win32StartAddress;                                                //0x4d0
    PVOID ChargeOnlySession;                                                //0x4d8
    PVOID LegacyPowerObject;                                                //0x4e0
    LIST_ENTRY ThreadListEntry;                                     //0x4e8
    EX_RUNDOWN_REF RundownProtect;                                  //0x4f8
    EX_PUSH_LOCK ThreadLock;                                        //0x500
    ULONG ReadClusterSize;                                                  //0x508
    volatile LONG MmLockOrdering;                                           //0x50c
    union
    {
        ULONG CrossThreadFlags;                                             //0x510
        struct
        {
            ULONG Terminated : 1;                                             //0x510
            ULONG ThreadInserted : 1;                                         //0x510
            ULONG HideFromDebugger : 1;                                       //0x510
            ULONG ActiveImpersonationInfo : 1;                                //0x510
            ULONG HardErrorsAreDisabled : 1;                                  //0x510
            ULONG BreakOnTermination : 1;                                     //0x510
            ULONG SkipCreationMsg : 1;                                        //0x510
            ULONG SkipTerminationMsg : 1;                                     //0x510
            ULONG CopyTokenOnOpen : 1;                                        //0x510
            ULONG ThreadIoPriority : 3;                                       //0x510
            ULONG ThreadPagePriority : 3;                                     //0x510
            ULONG RundownFail : 1;                                            //0x510
            ULONG UmsForceQueueTermination : 1;                               //0x510
            ULONG IndirectCpuSets : 1;                                        //0x510
            ULONG DisableDynamicCodeOptOut : 1;                               //0x510
            ULONG ExplicitCaseSensitivity : 1;                                //0x510
            ULONG PicoNotifyExit : 1;                                         //0x510
            ULONG DbgWerUserReportActive : 1;                                 //0x510
            ULONG ForcedSelfTrimActive : 1;                                   //0x510
            ULONG SamplingCoverage : 1;                                       //0x510
            ULONG ReservedCrossThreadFlags : 8;                               //0x510
        };
    };
    union
    {
        ULONG SameThreadPassiveFlags;                                       //0x514
        struct
        {
            ULONG ActiveExWorker : 1;                                         //0x514
            ULONG MemoryMaker : 1;                                            //0x514
            ULONG StoreLockThread : 2;                                        //0x514
            ULONG ClonedThread : 1;                                           //0x514
            ULONG KeyedEventInUse : 1;                                        //0x514
            ULONG SelfTerminate : 1;                                          //0x514
            ULONG RespectIoPriority : 1;                                      //0x514
            ULONG ActivePageLists : 1;                                        //0x514
            ULONG SecureContext : 1;                                          //0x514
            ULONG ZeroPageThread : 1;                                         //0x514
            ULONG WorkloadClass : 1;                                          //0x514
            ULONG ReservedSameThreadPassiveFlags : 20;                        //0x514
        };
    };
    union
    {
        ULONG SameThreadApcFlags;                                           //0x518
        struct
        {
            UCHAR OwnsProcessAddressSpaceExclusive : 1;                       //0x518
            UCHAR OwnsProcessAddressSpaceShared : 1;                          //0x518
            UCHAR HardFaultBehavior : 1;                                      //0x518
            volatile UCHAR StartAddressInvalid : 1;                           //0x518
            UCHAR EtwCalloutActive : 1;                                       //0x518
            UCHAR SuppressSymbolLoad : 1;                                     //0x518
            UCHAR Prefetching : 1;                                            //0x518
            UCHAR OwnsVadExclusive : 1;                                       //0x518
            UCHAR SystemPagePriorityActive : 1;                               //0x519
            UCHAR SystemPagePriority : 3;                                     //0x519
            UCHAR AllowUserWritesToExecutableMemory : 1;                      //0x519
            UCHAR AllowKernelWritesToExecutableMemory : 1;                    //0x519
            UCHAR OwnsVadShared : 1;                                          //0x519
        };
    };
    UCHAR CacheManagerActive;                                               //0x51c
    UCHAR DisablePageFaultClustering;                                       //0x51d
    UCHAR ActiveFaultCount;                                                 //0x51e
    UCHAR LockOrderState;                                                   //0x51f
    ULONG PerformanceCountLowReserved;                                      //0x520
    LONG PerformanceCountHighReserved;                                      //0x524
    ULONGLONG AlpcMessageId;                                                //0x528
    union
    {
        PVOID AlpcMessage;                                                  //0x530
        ULONG AlpcReceiveAttributeSet;                                      //0x530
    };
    LIST_ENTRY AlpcWaitListEntry;                                   //0x538
    LONG ExitStatus;                                                        //0x548
    ULONG CacheManagerCount;                                                //0x54c
    ULONG IoBoostCount;                                                     //0x550
    ULONG IoQoSBoostCount;                                                  //0x554
    ULONG IoQoSThrottleCount;                                               //0x558
    ULONG KernelStackReference;                                             //0x55c
    LIST_ENTRY BoostList;                                           //0x560
    LIST_ENTRY DeboostList;                                         //0x570
    ULONGLONG BoostListLock;                                                //0x580
    ULONGLONG IrpListLock;                                                  //0x588
    PVOID ReservedForSynchTracking;                                         //0x590
    SINGLE_LIST_ENTRY CmCallbackListHead;                           //0x598
    GUID* ActivityId;                                               //0x5a0
    SINGLE_LIST_ENTRY SeLearningModeListHead;                       //0x5a8
    PVOID VerifierContext;                                                  //0x5b0
    PVOID AdjustedClientToken;                                              //0x5b8
    PVOID WorkOnBehalfThread;                                               //0x5c0
    PS_PROPERTY_SET PropertySet;                                    //0x5c8
    PVOID PicoContext;                                                      //0x5e0
    ULONGLONG UserFsBase;                                                   //0x5e8
    ULONGLONG UserGsBase;                                                   //0x5f0
    struct _THREAD_ENERGY_VALUES* EnergyValues;                             //0x5f8
    union
    {
        ULONGLONG SelectedCpuSets;                                          //0x600
        ULONGLONG* SelectedCpuSetsIndirect;                                 //0x600
    };
    struct _EJOB* Silo;                                                     //0x608
    UNICODE_STRING* ThreadName;                                     //0x610
    CONTEXT* SetContextState;                                       //0x618
    ULONG LastExpectedRunTime;                                              //0x620
    ULONG HeapData;                                                         //0x624
    LIST_ENTRY OwnerEntryListHead;                                  //0x628
    ULONGLONG DisownedOwnerEntryListLock;                                   //0x638
    LIST_ENTRY DisownedOwnerEntryListHead;                          //0x640
    KLOCK_ENTRY LockEntries[6];                                     //0x650
    PVOID CmDbgInfo;                                                        //0x890
} ETHREAD_REAL, * PETHREAD_REAL;

typedef struct _MMSUPPORT_FLAGS
{
    union
    {
        struct
        {
            UCHAR WorkingSetType : 3;                                         //0x0
            UCHAR Reserved0 : 3;                                              //0x0
            UCHAR MaximumWorkingSetHard : 1;                                  //0x0
            UCHAR MinimumWorkingSetHard : 1;                                  //0x0
            UCHAR SessionMaster : 1;                                          //0x1
            UCHAR TrimmerState : 2;                                           //0x1
            UCHAR Reserved : 1;                                               //0x1
            UCHAR PageStealers : 4;                                           //0x1
        };
        USHORT u1;                                                          //0x0
    };
    UCHAR MemoryPriority;                                                   //0x2
    union
    {
        struct
        {
            UCHAR WsleDeleted : 1;                                            //0x3
            UCHAR SvmEnabled : 1;                                             //0x3
            UCHAR ForceAge : 1;                                               //0x3
            UCHAR ForceTrim : 1;                                              //0x3
            UCHAR NewMaximum : 1;                                             //0x3
            UCHAR CommitReleaseState : 2;                                     //0x3
        };
        UCHAR u2;                                                           //0x3
    };
} MMSUPPORT_FLAGS, * PMMSUPPORT_FLAGS;

typedef struct _MMSUPPORT_INSTANCE
{
    ULONG NextPageColor;                                                    //0x0
    ULONG PageFaultCount;                                                   //0x4
    ULONGLONG TrimmedPageCount;                                             //0x8
    struct _MMWSL_INSTANCE* VmWorkingSetList;                               //0x10
    LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
    ULONGLONG AgeDistribution[8];                                           //0x28
    PKGATE ExitOutswapGate;                                         //0x68
    ULONGLONG MinimumWorkingSetSize;                                        //0x70
    ULONGLONG WorkingSetLeafSize;                                           //0x78
    ULONGLONG WorkingSetLeafPrivateSize;                                    //0x80
    ULONGLONG WorkingSetSize;                                               //0x88
    ULONGLONG WorkingSetPrivateSize;                                        //0x90
    ULONGLONG MaximumWorkingSetSize;                                        //0x98
    ULONGLONG PeakWorkingSetSize;                                           //0xa0
    ULONG HardFaultCount;                                                   //0xa8
    USHORT LastTrimStamp;                                                   //0xac
    USHORT PartitionId;                                                     //0xae
    ULONGLONG SelfmapLock;                                                  //0xb0
    struct _MMSUPPORT_FLAGS Flags;                                          //0xb8
} MMSUPPORT_INSTANCE, * PMMSUPPORT_INSTANCE;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
    POBJECT_NAME_INFORMATION ImageFileName;                         //0x0
} SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _RTL_AVL_TREE
{
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
} RTL_AVL_TREE, * PRTL_AVL_TREE;

typedef struct _MMSUPPORT_SHARED
{
    volatile LONG WorkingSetLock;                                           //0x0
    LONG GoodCitizenWaiting;                                                //0x4
    ULONGLONG ReleasedCommitDebt;                                           //0x8
    ULONGLONG ResetPagesRepurposedCount;                                    //0x10
    PVOID WsSwapSupport;                                                    //0x18
    PVOID CommitReleaseContext;                                             //0x20
    PVOID AccessLog;                                                        //0x28
    volatile ULONGLONG ChargedWslePages;                                    //0x30
    ULONGLONG ActualWslePages;                                              //0x38
    ULONGLONG WorkingSetCoreLock;                                           //0x40
    PVOID ShadowMapping;                                                    //0x48
} MMSUPPORT_SHARED, * PMMSUPPORT_SHARED;

typedef struct _MMSUPPORT_FULL
{
    MMSUPPORT_INSTANCE Instance;                                    //0x0
    MMSUPPORT_SHARED Shared;                                        //0xc0
} MMSUPPORT_FULL, * PMMSUPPORT_FULL;

typedef struct _ALPC_PROCESS_CONTEXT
{
    EX_PUSH_LOCK Lock;                                              //0x0
    LIST_ENTRY ViewListHead;                                        //0x8
    volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
} ALPC_PROCESS_CONTEXT, * PALPC_PROCESS_CONTEXT;

typedef struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;                                                        //0x0
        struct
        {
            UCHAR Type : 3;                                                   //0x0
            UCHAR Audit : 1;                                                  //0x0
            UCHAR Signer : 4;                                                 //0x0
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _JOBOBJECT_WAKE_FILTER
{
    ULONG HighEdgeFilter;                                                   //0x0
    ULONG LowEdgeFilter;                                                    //0x4
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

typedef struct _PS_PROCESS_WAKE_INFORMATION
{
    ULONGLONG NotificationChannel;                                          //0x0
    ULONG WakeCounters[7];                                                  //0x8
    struct _JOBOBJECT_WAKE_FILTER WakeFilter;                               //0x24
    ULONG NoWakeCounter;                                                    //0x2c
} PS_PROCESS_WAKE_INFORMATION, * PPS_PROCESS_WAKE_INFORMATION;

typedef struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
{
    struct _RTL_AVL_TREE Tree;                                              //0x0
    struct _EX_PUSH_LOCK Lock;                                              //0x8
} PS_DYNAMIC_ENFORCED_ADDRESS_RANGES, * PPS_DYNAMIC_ENFORCED_ADDRESS_RANGES;

typedef union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
    ULONGLONG DelayMs : 30;                                                   //0x0
    ULONGLONG CoalescingWindowMs : 30;                                        //0x0
    ULONGLONG Reserved : 1;                                                   //0x0
    ULONGLONG NewTimerWheel : 1;                                              //0x0
    ULONGLONG Retry : 1;                                                      //0x0
    ULONGLONG Locked : 1;                                                     //0x0
    ULONGLONG All;                                                          //0x0
} PS_INTERLOCKED_TIMER_DELAY_VALUES, * PPS_INTERLOCKED_TIMER_DELAY_VALUES;

typedef struct _EPROCESS_REAL
{
    KPROCESS_REAL Pcb;                                                   //0x0
    EX_PUSH_LOCK ProcessLock;                                       //0x438
    PVOID UniqueProcessId;                                                  //0x440
    LIST_ENTRY ActiveProcessLinks;                                  //0x448
    EX_RUNDOWN_REF RundownProtect;                                  //0x458
    union
    {
        ULONG Flags2;                                                       //0x460
        struct
        {
            ULONG JobNotReallyActive : 1;                                     //0x460
            ULONG AccountingFolded : 1;                                       //0x460
            ULONG NewProcessReported : 1;                                     //0x460
            ULONG ExitProcessReported : 1;                                    //0x460
            ULONG ReportCommitChanges : 1;                                    //0x460
            ULONG LastReportMemory : 1;                                       //0x460
            ULONG ForceWakeCharge : 1;                                        //0x460
            ULONG CrossSessionCreate : 1;                                     //0x460
            ULONG NeedsHandleRundown : 1;                                     //0x460
            ULONG RefTraceEnabled : 1;                                        //0x460
            ULONG PicoCreated : 1;                                            //0x460
            ULONG EmptyJobEvaluated : 1;                                      //0x460
            ULONG DefaultPagePriority : 3;                                    //0x460
            ULONG PrimaryTokenFrozen : 1;                                     //0x460
            ULONG ProcessVerifierTarget : 1;                                  //0x460
            ULONG RestrictSetThreadContext : 1;                               //0x460
            ULONG AffinityPermanent : 1;                                      //0x460
            ULONG AffinityUpdateEnable : 1;                                   //0x460
            ULONG PropagateNode : 1;                                          //0x460
            ULONG ExplicitAffinity : 1;                                       //0x460
            ULONG ProcessExecutionState : 2;                                  //0x460
            ULONG EnableReadVmLogging : 1;                                    //0x460
            ULONG EnableWriteVmLogging : 1;                                   //0x460
            ULONG FatalAccessTerminationRequested : 1;                        //0x460
            ULONG DisableSystemAllowedCpuSet : 1;                             //0x460
            ULONG ProcessStateChangeRequest : 2;                              //0x460
            ULONG ProcessStateChangeInProgress : 1;                           //0x460
            ULONG InPrivate : 1;                                              //0x460
        };
    };
    union
    {
        ULONG Flags;                                                        //0x464
        struct
        {
            ULONG CreateReported : 1;                                         //0x464
            ULONG NoDebugInherit : 1;                                         //0x464
            ULONG ProcessExiting : 1;                                         //0x464
            ULONG ProcessDelete : 1;                                          //0x464
            ULONG ManageExecutableMemoryWrites : 1;                           //0x464
            ULONG VmDeleted : 1;                                              //0x464
            ULONG OutswapEnabled : 1;                                         //0x464
            ULONG Outswapped : 1;                                             //0x464
            ULONG FailFastOnCommitFail : 1;                                   //0x464
            ULONG Wow64VaSpace4Gb : 1;                                        //0x464
            ULONG AddressSpaceInitialized : 2;                                //0x464
            ULONG SetTimerResolution : 1;                                     //0x464
            ULONG BreakOnTermination : 1;                                     //0x464
            ULONG DeprioritizeViews : 1;                                      //0x464
            ULONG WriteWatch : 1;                                             //0x464
            ULONG ProcessInSession : 1;                                       //0x464
            ULONG OverrideAddressSpace : 1;                                   //0x464
            ULONG HasAddressSpace : 1;                                        //0x464
            ULONG LaunchPrefetched : 1;                                       //0x464
            ULONG Background : 1;                                             //0x464
            ULONG VmTopDown : 1;                                              //0x464
            ULONG ImageNotifyDone : 1;                                        //0x464
            ULONG PdeUpdateNeeded : 1;                                        //0x464
            ULONG VdmAllowed : 1;                                             //0x464
            ULONG ProcessRundown : 1;                                         //0x464
            ULONG ProcessInserted : 1;                                        //0x464
            ULONG DefaultIoPriority : 3;                                      //0x464
            ULONG ProcessSelfDelete : 1;                                      //0x464
            ULONG SetTimerResolutionLink : 1;                                 //0x464
        };
    };
    LARGE_INTEGER CreateTime;                                        //0x468
    ULONGLONG ProcessQuotaUsage[2];                                         //0x470
    ULONGLONG ProcessQuotaPeak[2];                                          //0x480
    ULONGLONG PeakVirtualSize;                                              //0x490
    ULONGLONG VirtualSize;                                                  //0x498
    LIST_ENTRY SessionProcessLinks;                                 //0x4a0
    union
    {
        PVOID ExceptionPortData;                                            //0x4b0
        ULONGLONG ExceptionPortValue;                                       //0x4b0
        ULONGLONG ExceptionPortState : 3;                                     //0x4b0
    };
    EX_FAST_REF Token;                                              //0x4b8
    ULONGLONG MmReserved;                                                   //0x4c0
    EX_PUSH_LOCK AddressCreationLock;                               //0x4c8
    EX_PUSH_LOCK PageTableCommitmentLock;                           //0x4d0
    ETHREAD_REAL* RotateInProgress;                                      //0x4d8
    ETHREAD_REAL* ForkInProgress;                                        //0x4e0
    struct _EJOB* volatile CommitChargeJob;                                 //0x4e8
    RTL_AVL_TREE CloneRoot;                                         //0x4f0
    volatile ULONGLONG NumberOfPrivatePages;                                //0x4f8
    volatile ULONGLONG NumberOfLockedPages;                                 //0x500
    PVOID Win32Process;                                                     //0x508
    struct _EJOB* volatile Job;                                             //0x510
    PVOID SectionObject;                                                    //0x518
    PVOID SectionBaseAddress;                                               //0x520
    ULONG Cookie;                                                           //0x528
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x530
    PVOID Win32WindowStation;                                               //0x538
    PVOID InheritedFromUniqueProcessId;                                     //0x540
    volatile ULONGLONG OwnerProcessId;                                      //0x548
    struct _PEB* Peb;                                                       //0x550
    struct _MM_SESSION_SPACE* Session;                                      //0x558
    PVOID Spare1;                                                           //0x560
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x568
    struct _HANDLE_TABLE* ObjectTable;                                      //0x570
    PVOID DebugPort;                                                        //0x578
    struct _EWOW64PROCESS* WoW64Process;                                    //0x580
    PVOID DeviceMap;                                                        //0x588
    PVOID EtwDataSource;                                                    //0x590
    ULONGLONG PageDirectoryPte;                                             //0x598
    FILE_OBJECT* ImageFilePointer;                                  //0x5a0
    UCHAR ImageFileName[15];                                                //0x5a8
    UCHAR PriorityClass;                                                    //0x5b7
    PVOID SecurityPort;                                                     //0x5b8
    SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x5c0
    LIST_ENTRY JobLinks;                                            //0x5c8
    PVOID HighestUserAddress;                                               //0x5d8
    LIST_ENTRY ThreadListHead;                                      //0x5e0
    volatile ULONG ActiveThreads;                                           //0x5f0
    ULONG ImagePathHash;                                                    //0x5f4
    ULONG DefaultHardErrorProcessing;                                       //0x5f8
    LONG LastThreadExitStatus;                                              //0x5fc
    EX_FAST_REF PrefetchTrace;                                      //0x600
    PVOID LockedPagesList;                                                  //0x608
    union _LARGE_INTEGER ReadOperationCount;                                //0x610
    union _LARGE_INTEGER WriteOperationCount;                               //0x618
    union _LARGE_INTEGER OtherOperationCount;                               //0x620
    union _LARGE_INTEGER ReadTransferCount;                                 //0x628
    union _LARGE_INTEGER WriteTransferCount;                                //0x630
    union _LARGE_INTEGER OtherTransferCount;                                //0x638
    ULONGLONG CommitChargeLimit;                                            //0x640
    volatile ULONGLONG CommitCharge;                                        //0x648
    volatile ULONGLONG CommitChargePeak;                                    //0x650
    MMSUPPORT_FULL Vm;                                              //0x680
    LIST_ENTRY MmProcessLinks;                                      //0x7c0
    ULONG ModifiedPageCount;                                                //0x7d0
    LONG ExitStatus;                                                        //0x7d4
    RTL_AVL_TREE VadRoot;                                           //0x7d8
    PVOID VadHint;                                                          //0x7e0
    ULONGLONG VadCount;                                                     //0x7e8
    volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
    ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
    ALPC_PROCESS_CONTEXT AlpcContext;                               //0x800
    LIST_ENTRY TimerResolutionLink;                                 //0x820
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x830
    ULONG RequestedTimerResolution;                                         //0x838
    ULONG SmallestTimerResolution;                                          //0x83c
    union _LARGE_INTEGER ExitTime;                                          //0x840
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x848
    EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x850
    ULONG ActiveThreadsHighWatermark;                                       //0x858
    ULONG LargePrivateVadCount;                                             //0x85c
    EX_PUSH_LOCK ThreadListLock;                                    //0x860
    PVOID WnfContext;                                                       //0x868
    struct _EJOB* ServerSilo;                                               //0x870
    UCHAR SignatureLevel;                                                   //0x878
    UCHAR SectionSignatureLevel;                                            //0x879
    PS_PROTECTION Protection;                                       //0x87a
    UCHAR HangCount : 3;                                                      //0x87b
    UCHAR GhostCount : 3;                                                     //0x87b
    UCHAR PrefilterException : 1;                                             //0x87b
    union
    {
        ULONG Flags3;                                                       //0x87c
        struct
        {
            ULONG Minimal : 1;                                                //0x87c
            ULONG ReplacingPageRoot : 1;                                      //0x87c
            ULONG Crashed : 1;                                                //0x87c
            ULONG JobVadsAreTracked : 1;                                      //0x87c
            ULONG VadTrackingDisabled : 1;                                    //0x87c
            ULONG AuxiliaryProcess : 1;                                       //0x87c
            ULONG SubsystemProcess : 1;                                       //0x87c
            ULONG IndirectCpuSets : 1;                                        //0x87c
            ULONG RelinquishedCommit : 1;                                     //0x87c
            ULONG HighGraphicsPriority : 1;                                   //0x87c
            ULONG CommitFailLogged : 1;                                       //0x87c
            ULONG ReserveFailLogged : 1;                                      //0x87c
            ULONG SystemProcess : 1;                                          //0x87c
            ULONG HideImageBaseAddresses : 1;                                 //0x87c
            ULONG AddressPolicyFrozen : 1;                                    //0x87c
            ULONG ProcessFirstResume : 1;                                     //0x87c
            ULONG ForegroundExternal : 1;                                     //0x87c
            ULONG ForegroundSystem : 1;                                       //0x87c
            ULONG HighMemoryPriority : 1;                                     //0x87c
            ULONG EnableProcessSuspendResumeLogging : 1;                      //0x87c
            ULONG EnableThreadSuspendResumeLogging : 1;                       //0x87c
            ULONG SecurityDomainChanged : 1;                                  //0x87c
            ULONG SecurityFreezeComplete : 1;                                 //0x87c
            ULONG VmProcessorHost : 1;                                        //0x87c
            ULONG VmProcessorHostTransition : 1;                              //0x87c
            ULONG AltSyscall : 1;                                             //0x87c
            ULONG TimerResolutionIgnore : 1;                                  //0x87c
            ULONG DisallowUserTerminate : 1;                                  //0x87c
        };
    };
    LONG DeviceAsid;                                                        //0x880
    PVOID SvmData;                                                          //0x888
    EX_PUSH_LOCK SvmProcessLock;                                    //0x890
    ULONGLONG SvmLock;                                                      //0x898
    LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
    ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x8b8
    PVOID PicoContext;                                                      //0x8c0
    PVOID EnclaveTable;                                                     //0x8c8
    ULONGLONG EnclaveNumber;                                                //0x8d0
    EX_PUSH_LOCK EnclaveLock;                                       //0x8d8
    ULONG HighPriorityFaultsAllowed;                                        //0x8e0
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x8e8
    PVOID VmContext;                                                        //0x8f0
    ULONGLONG SequenceNumber;                                               //0x8f8
    ULONGLONG CreateInterruptTime;                                          //0x900
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
    ULONGLONG LastAppStateUpdateTime;                                       //0x918
    ULONGLONG LastAppStateUptime : 61;                                        //0x920
    ULONGLONG LastAppState : 3;                                               //0x920
    volatile ULONGLONG SharedCommitCharge;                                  //0x928
    EX_PUSH_LOCK SharedCommitLock;                                  //0x930
    LIST_ENTRY SharedCommitLinks;                                   //0x938
    union
    {
        struct
        {
            ULONGLONG AllowedCpuSets;                                       //0x948
            ULONGLONG DefaultCpuSets;                                       //0x950
        };
        struct
        {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
        };
    };
    PVOID DiskIoAttribution;                                                //0x958
    PVOID DxgProcess;                                                       //0x960
    ULONG Win32KFilterSet;                                                  //0x968
    volatile union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;     //0x970
    volatile ULONG KTimerSets;                                              //0x978
    volatile ULONG KTimer2Sets;                                             //0x97c
    volatile ULONG ThreadTimerSets;                                         //0x980
    ULONGLONG VirtualTimerListLock;                                         //0x988
    LIST_ENTRY VirtualTimerListHead;                                //0x990
    union
    {
        WNF_STATE_NAME WakeChannel;                                 //0x9a0
        PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x9a0
    };
    union
    {
        ULONG MitigationFlags;                                              //0x9d0
        struct
        {
            ULONG ControlFlowGuardEnabled : 1;                                //0x9d0
            ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x9d0
            ULONG ControlFlowGuardStrict : 1;                                 //0x9d0
            ULONG DisallowStrippedImages : 1;                                 //0x9d0
            ULONG ForceRelocateImages : 1;                                    //0x9d0
            ULONG HighEntropyASLREnabled : 1;                                 //0x9d0
            ULONG StackRandomizationDisabled : 1;                             //0x9d0
            ULONG ExtensionPointDisable : 1;                                  //0x9d0
            ULONG DisableDynamicCode : 1;                                     //0x9d0
            ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x9d0
            ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x9d0
            ULONG AuditDisableDynamicCode : 1;                                //0x9d0
            ULONG DisallowWin32kSystemCalls : 1;                              //0x9d0
            ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x9d0
            ULONG EnableFilteredWin32kAPIs : 1;                               //0x9d0
            ULONG AuditFilteredWin32kAPIs : 1;                                //0x9d0
            ULONG DisableNonSystemFonts : 1;                                  //0x9d0
            ULONG AuditNonSystemFontLoading : 1;                              //0x9d0
            ULONG PreferSystem32Images : 1;                                   //0x9d0
            ULONG ProhibitRemoteImageMap : 1;                                 //0x9d0
            ULONG AuditProhibitRemoteImageMap : 1;                            //0x9d0
            ULONG ProhibitLowILImageMap : 1;                                  //0x9d0
            ULONG AuditProhibitLowILImageMap : 1;                             //0x9d0
            ULONG SignatureMitigationOptIn : 1;                               //0x9d0
            ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x9d0
            ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x9d0
            ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x9d0
            ULONG AuditLoaderIntegrityContinuity : 1;                         //0x9d0
            ULONG EnableModuleTamperingProtection : 1;                        //0x9d0
            ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x9d0
            ULONG RestrictIndirectBranchPrediction : 1;                       //0x9d0
            ULONG IsolateSecurityDomain : 1;                                  //0x9d0
        } MitigationFlagsValues;                                            //0x9d0
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x9d4
        struct
        {
            ULONG EnableExportAddressFilter : 1;                              //0x9d4
            ULONG AuditExportAddressFilter : 1;                               //0x9d4
            ULONG EnableExportAddressFilterPlus : 1;                          //0x9d4
            ULONG AuditExportAddressFilterPlus : 1;                           //0x9d4
            ULONG EnableRopStackPivot : 1;                                    //0x9d4
            ULONG AuditRopStackPivot : 1;                                     //0x9d4
            ULONG EnableRopCallerCheck : 1;                                   //0x9d4
            ULONG AuditRopCallerCheck : 1;                                    //0x9d4
            ULONG EnableRopSimExec : 1;                                       //0x9d4
            ULONG AuditRopSimExec : 1;                                        //0x9d4
            ULONG EnableImportAddressFilter : 1;                              //0x9d4
            ULONG AuditImportAddressFilter : 1;                               //0x9d4
            ULONG DisablePageCombine : 1;                                     //0x9d4
            ULONG SpeculativeStoreBypassDisable : 1;                          //0x9d4
            ULONG CetUserShadowStacks : 1;                                    //0x9d4
            ULONG AuditCetUserShadowStacks : 1;                               //0x9d4
            ULONG AuditCetUserShadowStacksLogged : 1;                         //0x9d4
            ULONG UserCetSetContextIpValidation : 1;                          //0x9d4
            ULONG AuditUserCetSetContextIpValidation : 1;                     //0x9d4
            ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x9d4
            ULONG CetUserShadowStacksStrictMode : 1;                          //0x9d4
            ULONG BlockNonCetBinaries : 1;                                    //0x9d4
            ULONG BlockNonCetBinariesNonEhcont : 1;                           //0x9d4
            ULONG AuditBlockNonCetBinaries : 1;                               //0x9d4
            ULONG AuditBlockNonCetBinariesLogged : 1;                         //0x9d4
            ULONG Reserved1 : 1;                                              //0x9d4
            ULONG Reserved2 : 1;                                              //0x9d4
            ULONG Reserved3 : 1;                                              //0x9d4
            ULONG Reserved4 : 1;                                              //0x9d4
            ULONG Reserved5 : 1;                                              //0x9d4
            ULONG CetDynamicApisOutOfProcOnly : 1;                            //0x9d4
            ULONG UserCetSetContextIpValidationRelaxedMode : 1;               //0x9d4
        } MitigationFlags2Values;                                           //0x9d4
    };
    PVOID PartitionObject;                                                  //0x9d8
    ULONGLONG SecurityDomain;                                               //0x9e0
    ULONGLONG ParentSecurityDomain;                                         //0x9e8
    PVOID CoverageSamplerContext;                                           //0x9f0
    PVOID MmHotPatchContext;                                                //0x9f8
    RTL_AVL_TREE DynamicEHContinuationTargetsTree;                  //0xa00
    EX_PUSH_LOCK DynamicEHContinuationTargetsLock;                  //0xa08
    PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges; //0xa10
    ULONG DisabledComponentFlags;                                           //0xa20
} EPROCESS_REAL, * PEPROCESS_REAL;

#endif
