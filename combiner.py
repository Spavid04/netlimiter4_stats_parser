import dataclasses
import os.path
import shutil
import typing

import netlimiter_stats_parser as nsp

@dataclasses.dataclass()
class Pack():
    nlstatsv4Path: str
    nlstatsv6Path: str
    appsPath: str
    usersPath: str

    def Clear(self):
        if os.path.exists(self.nlstatsv4Path): os.remove(self.nlstatsv4Path)
        if os.path.exists(self.nlstatsv6Path): os.remove(self.nlstatsv6Path)
        if os.path.exists(self.appsPath): os.remove(self.appsPath)
        if os.path.exists(self.usersPath): os.remove(self.usersPath)

    def CopyTo(self, other: "Pack"):
        shutil.copyfile(self.nlstatsv4Path, other.nlstatsv4Path)
        shutil.copyfile(self.nlstatsv6Path, other.nlstatsv6Path)
        shutil.copyfile(self.appsPath, other.appsPath)
        shutil.copyfile(self.usersPath, other.usersPath)

def _create_new(path: str) -> typing.BinaryIO:
    assert not os.path.exists(path)
    return open(path, "wb")
class _PackData():
    def __init__(self, pack: Pack, writable: bool):
        self.pack = pack
        self.writable = writable

        self.nlstatsv4FD: typing.BinaryIO = None
        self.nlstatsv6FD: typing.BinaryIO = None
        self.appsFD: typing.BinaryIO = None
        self.usersFD: typing.BinaryIO = None

        self.opened = False
        self.closed = False

    def open_files(self):
        if self.opened:
            return
        self.opened = True

        opener = None
        if self.writable:
            opener = lambda path: _create_new(path)
        else:
            opener = lambda path: open(path, "rb")

        self.nlstatsv4FD = opener(self.pack.nlstatsv4Path)
        self.nlstatsv6FD = opener(self.pack.nlstatsv6Path)
        self.appsFD = opener(self.pack.appsPath)
        self.usersFD = opener(self.pack.usersPath)

    def close(self):
        if self.closed:
            return
        self.closed = True

        if self.nlstatsv4FD:
            self.nlstatsv4FD.close()
        if self.nlstatsv6FD:
            self.nlstatsv6FD.close()
        if self.appsFD:
            self.appsFD.close()
        if self.usersFD:
            self.usersFD.close()

    def __enter__(self):
        self.open_files()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

T = typing.TypeVar("T", bound=typing.Hashable)
# NOTE: resulting ID's should be treated as offsets (starting at 1) above the highest id value in the base
# eg: resulting id=1 means [the highest appid row from the base] + 1
def _separateNewAddends(base: typing.Iterable[T], addend: typing.Iterable[T]) \
        -> typing.Dict[T, int]:
    addendMapping = dict()
    offset = 1
    for item in addend:
        if item in base:
            continue

        addendMapping[item] = offset
        offset += 1

    return addendMapping

def _yield_ordered_rows(baseGenerator: typing.Generator[nsp.StatsRow, None, None], addendGenerator: typing.Generator[nsp.StatsRow, None, None]) \
        -> typing.Generator[typing.Tuple[typing.Union[nsp.RawStatsRowV4 | nsp.RawStatsRowV6], bool], None, None]:
    basePtr = next(baseGenerator)
    addendPtr = next(addendGenerator)
    while True:
        nextRow = None
        fromAddend = False

        if basePtr is None:
            nextRow = addendPtr.raw_row
            addendPtr = next(addendGenerator, None)
            fromAddend = True
        elif addendPtr is None:
            nextRow = basePtr.raw_row
            basePtr = next(baseGenerator, None)
        else:
            if basePtr.raw_timestamp <= addendPtr.raw_timestamp:
                nextRow = basePtr.raw_row
                basePtr = next(baseGenerator, None)
            else:
                nextRow = addendPtr.raw_row
                addendPtr = next(addendGenerator, None)
                fromAddend = True

        if nextRow is None:
            break

        yield (nextRow, fromAddend)

def _combine(base: _PackData, addend: _PackData, result: _PackData):
    #region app merging
    baseApps = list(nsp.get_apps(base.appsFD))
    baseAppsMapping = dict()
    for row in baseApps:
        baseAppsMapping[row.path] = row.app_id

    addendApps = list(nsp.get_apps(addend.appsFD))
    addendAppsMapping = dict()
    for row in addendApps:
        addendAppsMapping[row.app_id] = row.path

    newAppsInAddend = _separateNewAddends(baseAppsMapping.keys(), addendAppsMapping.values())
    maxBaseAppId = max(x for x in baseAppsMapping.values())
    for key in newAppsInAddend:
        newAppsInAddend[key] += maxBaseAppId
    #endregion

    #region user merging
    baseUsers = list(nsp.get_users(base.usersFD))
    baseUsersMapping = dict()
    for row in baseUsers:
        baseUsersMapping[row.sid] = row.user_id

    addendUsers = list(nsp.get_users(addend.usersFD))
    addendUsersMapping = dict()
    for row in addendUsers:
        addendUsersMapping[row.user_id] = row.sid

    newUsersInAddend = _separateNewAddends(baseUsersMapping.keys(), addendUsersMapping.values())
    maxBaseUserId = max(x for x in baseUsersMapping.values())
    for key in newUsersInAddend:
        newUsersInAddend[key] += maxBaseUserId
    #endregion

    def copy_stat_rows(baseFd: typing.BinaryIO, addendFd: typing.BinaryIO, resultFd: typing.BinaryIO, ipv6: bool):
        for (row, fromAddend) in _yield_ordered_rows(nsp.get_rows(baseFd, ipv6), nsp.get_rows(addendFd, ipv6)):
            if fromAddend:
                # update appid if needed
                if row.transfer_data.app_id != 0:
                    # appid 0 is special (system?)
                    oldAppId = row.transfer_data.app_id
                    path = addendAppsMapping[oldAppId]
                    if path in newAppsInAddend:
                        newAppId = newAppsInAddend[path]
                        row.transfer_data.app_id = newAppId

                # update userid if needed
                oldUserId = row.transfer_data.user_id
                sid = addendUsersMapping[oldUserId]
                if sid in newUsersInAddend:
                    newUserId = newUsersInAddend[sid]
                    row.transfer_data.user_id = newUserId

            resultFd.write(bytearray(row))

    for app in sorted(baseApps, key=lambda x: x.app_id):
        result.appsFD.write(app.to_bytes())
    for (path, app_id) in sorted(newAppsInAddend.items(), key=lambda x: x[1]):
        result.appsFD.write(nsp.AppRow(app_id, path).to_bytes())

    for user in sorted(baseUsers, key=lambda x: x.user_id):
        result.usersFD.write(user.to_bytes())
    for (sid, user_id) in sorted(newUsersInAddend.items(), key=lambda x: x[1]):
        result.usersFD.write(nsp.UserRow(user_id, sid).to_bytes())

    copy_stat_rows(base.nlstatsv4FD, addend.nlstatsv4FD, result.nlstatsv4FD, False)

    copy_stat_rows(base.nlstatsv6FD, addend.nlstatsv6FD, result.nlstatsv6FD, True)

def combine(basePack: Pack, addendPack: Pack, resultPack: Pack):
    base = _PackData(basePack, False)
    addend = _PackData(addendPack, False)
    result = _PackData(resultPack, True)

    with base, addend, result:
        _combine(base, addend, result)
