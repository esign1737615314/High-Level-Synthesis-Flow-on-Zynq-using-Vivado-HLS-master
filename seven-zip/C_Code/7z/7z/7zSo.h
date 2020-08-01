#include <string.h>
#include <iterator>
#include "Common.h"
#include "ai.h"
using namespace std;

#ifdef __cplusplus
extern "C" {
#endif
    int iExeCase(const CaseInfoSeq & seqCaseInfo, CaseInfoStatusSeq & seqCaseInfoStatus
        , string &sErr, funOutpuDebugInfo fOpDebugInfo);
    int iAutoGenCase(const int & iCaseNum, const int &iPwdLen,CaseInfoSeq & seqCaseInfo
        , string & sErr, funOutpuDebugInfo fOpDebugInfo);
    int iGenCase(const string & sCaseDescInfo, CaseInfoSeq & seqCaseInfo, string & sErr
        , funOutpuDebugInfo fOpDebugInfo);
    int iGenCaseByFile(const string & sCaseDescInfoFile, CaseInfoSeq & seqCaseInfo
        , string & sErr, funOutpuDebugInfo fOpDebugInfo);
#ifdef __cplusplus
}
#endif
