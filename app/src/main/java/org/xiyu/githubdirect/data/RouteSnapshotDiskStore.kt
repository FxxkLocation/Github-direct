package org.xiyu.githubdirect.data

import android.content.Context
import android.util.AtomicFile
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import org.xiyu.githubdirect.core.routing.RouteSnapshotCodec
import java.io.File

/** 模块私有目录中的原子路由快照；写失败时 AtomicFile 自动保留上一份完整内容。 */
class RouteSnapshotDiskStore(context: Context) {
    private val directory = File(context.filesDir, "routes")
    private val file = AtomicFile(File(directory, "github_routes.json"))

    fun read(): RouteSnapshot? {
        if (!file.baseFile.isFile) return null
        return try {
            file.openRead().bufferedReader(Charsets.UTF_8).use { reader ->
                RouteSnapshotCodec.decode(reader.readText())
            }
        } catch (_: Throwable) {
            null
        }
    }

    @Synchronized
    fun write(snapshot: RouteSnapshot): Boolean {
        if (!directory.exists() && !directory.mkdirs()) return false
        val output = try {
            file.startWrite()
        } catch (_: Throwable) {
            return false
        }
        return try {
            output.writer(Charsets.UTF_8).apply {
                write(RouteSnapshotCodec.encode(snapshot))
                flush()
            }
            file.finishWrite(output)
            true
        } catch (_: Throwable) {
            try {
                file.failWrite(output)
            } catch (_: Throwable) {
            }
            false
        }
    }
}
