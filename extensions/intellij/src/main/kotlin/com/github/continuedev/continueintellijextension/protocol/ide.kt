package com.github.continuedev.continueintellijextension.protocol

import com.github.continuedev.continueintellijextension.Range
import com.github.continuedev.continueintellijextension.TerminalOptions


// Add these message type constants
const val MESSAGE_TYPE_MCP_OAUTH_REQUEST = "mcpOAuthRequest"
const val MESSAGE_TYPE_MCP_OAUTH_CALLBACK = "mcpOAuthCallback"
const val MESSAGE_TYPE_MCP_GET_CONFIG = "mcpGetConfig"

// Add data classes for messages
data class McpOAuthRequestMessage(
    val messageType: String = MESSAGE_TYPE_MCP_OAUTH_REQUEST,
    val serverName: String,
//    val oauthConfig: OAuthConfig todo
)

data class McpOAuthCallbackMessage(
    val messageType: String = MESSAGE_TYPE_MCP_OAUTH_CALLBACK,
    val serverName: String,
    val code: String,
    val state: String
)

data class McpConfigMessage(
    val messageType: String = MESSAGE_TYPE_MCP_GET_CONFIG,
    val serverName: String
)

data class GetControlPlaneSessionInfoParams(val silent: Boolean, val useOnboarding: Boolean)

data class WriteFileParams(
    val path: String,
    val contents: String
)

data class ShowVirtualFileParams(
    val name: String,
    val content: String
)


data class OpenFileParams(val path: String)

typealias OpenUrlParam = String

typealias getTagsParams = String

data class GetSearchResultsParams(val query: String, val maxResults: Int?)

data class GetFileResultsParams(val pattern: String, val maxResults: Int?)

data class SaveFileParams(val filepath: String)

data class FileExistsParams(val filepath: String)

data class ReadFileParams(val filepath: String)

data class ShowDiffParams(
    val filepath: String,
    val newContents: String,
    val stepIndex: Int
)

data class ShowLinesParams(
    val filepath: String,
    val startLine: Int,
    val endLine: Int
)

data class ReadRangeInFileParams(
    val filepath: String,
    val range: Range
)


data class GetDiffParams(val includeUnstaged: Boolean)

data class GetBranchParams(val dir: String)

data class GetRepoNameParams(val dir: String)

data class GetGitRootPathParams(val dir: String)

data class ListDirParams(val dir: String)

data class GetFileStatsParams(val files: List<String>)

data class RunCommandParams(val command: String, val options: TerminalOptions?)
