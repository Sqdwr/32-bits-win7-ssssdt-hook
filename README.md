# 32-bits-win7-ssssdt-hook
hook the sssdt to make taskmgr can't show the calc.
- hook the NtUserBuildHwndList
- first, find sssdt from keaddservicetable.
- second, find calc processid and csrss eprocess.
- then, in MyNtUserBuildHwndList I hide the calc window,make the taskmgr can’t find it.
