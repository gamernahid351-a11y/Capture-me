package com.ffcapture.model

object Constants {
    // ── AES static key (MajorLogin only) ──
    val AES_KEY: ByteArray = "Yg&tc%DEuh6%Zc^8".toByteArray(Charsets.UTF_8)
    val AES_IV:  ByteArray = "6oyZDr22E3ychjM%".toByteArray(Charsets.UTF_8)

    // ── Local ports ──
    const val HTTP_PORT       = 3030
    const val TCP_ONLINE_PORT = 7090
    const val TCP_CHAT_PORT   = 7080
    const val UDP_MATCH_PORT  = 5080

    // ── Packet type constants ──
    val SKIP_PACKET_TYPES = setOf("0214", "0215")
    val MATCH_FRAME_TYPES = setOf("0300", "0e00")
    const val MAJOR_LOGIN_OFFSET = 64

    // ── AES try offsets ──
    val AES_OFFSETS = intArrayOf(0, 1, 2, 3, 4, 5, 6, 8, 12, 16)

    // ── Free Fire IND hosts ──
    const val HOST_LOGIN    = "loginbp.ppmainecoonghj.com"
    const val HOST_CLIENT   = "client.ind.freefiremobile.com"
    const val HOST_BP       = "clientbp.ppmainecoonghj.com"

    // ── Route map: path → real host ──
    val ROUTE_BY_PATH: Map<String, String> = mapOf(
        "/MajorLogin"            to HOST_LOGIN,
        "/MajorRegister"         to HOST_LOGIN,
        "/GenerateNickname"      to HOST_LOGIN,
        "/ChooseNewbieChoice"    to HOST_LOGIN,
        "/ChooseRegion"          to HOST_LOGIN,
        "/GetLoginData"          to HOST_CLIENT,
        "/GetWallet"             to HOST_CLIENT,
        "/Ping"                  to HOST_CLIENT,
        "/GetConfig"             to HOST_CLIENT,
        "/GetRegionConfig"       to HOST_CLIENT,
        "/GetAnnouncement"       to HOST_CLIENT,
        "/GetStore"              to HOST_CLIENT,
        "/GetStoreItems"         to HOST_CLIENT,
        "/GetInventory"          to HOST_CLIENT,
        "/GetPets"               to HOST_CLIENT,
        "/GetLoadout"            to HOST_CLIENT,
        "/GetLoadoutList"        to HOST_CLIENT,
        "/GetAchievement"        to HOST_CLIENT,
        "/GetQuest"              to HOST_CLIENT,
        "/GetMission"            to HOST_CLIENT,
        "/GetEvent"              to HOST_CLIENT,
        "/GetEvents"             to HOST_CLIENT,
        "/GetMail"               to HOST_CLIENT,
        "/GetMailList"           to HOST_CLIENT,
        "/GetLobby"              to HOST_CLIENT,
        "/GetLobbyInfo"          to HOST_CLIENT,
        "/GetTeam"               to HOST_CLIENT,
        "/GetTeamInfo"           to HOST_CLIENT,
        "/CreateClan"            to HOST_BP,
        "/GetClanMainPageInfo"   to HOST_BP,
        "/GetClanMembers"        to HOST_BP,
        "/GetClanInfo"           to HOST_BP,
        "/GetPlayerPersonalShow" to HOST_BP,
        "/GetPlayerProfile"      to HOST_BP,
        "/GetPlayerStats"        to HOST_BP,
        "/GetPlayerBasicInfo"    to HOST_BP,
        "/GetRankInfo"           to HOST_BP,
        "/GetRankingList"        to HOST_BP,
        "/GetLeaderboard"        to HOST_BP,
        "/GetFriendList"         to HOST_BP,
        "/SendFriendRequest"     to HOST_BP,
        "/SearchPlayer"          to HOST_BP,
        "/GetRecent"             to HOST_BP
    )

    const val NOTIFICATION_CHANNEL_ID = "ff_capture_channel"
    const val NOTIFICATION_ID = 1337

    const val CHANNEL_HTTP   = "HTTP"
    const val CHANNEL_TCP    = "TCP"
    const val CHANNEL_UDP    = "UDP"
}
