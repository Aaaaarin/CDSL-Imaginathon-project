// AgentSnap Android signals. Reference implementation: not compiled in this
// repository (no Android toolchain on the build machine). Every value it returns is
// a boolean, a number or a keyed hash; no audio, screen content or contact list
// leaves the device.
//
// Manifest: READ_PHONE_STATE (call state), QUERY_ALL_PACKAGES is NOT needed: declare
// the remote-control packages below in <queries>. Caller identity needs the
// call-screening role (RoleManager.ROLE_CALL_SCREENING); without it caller_h is omitted
// and the server treats the caller as unverified.
package `in`.agentsnap.sdk

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Build
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import android.view.Display
import android.view.accessibility.AccessibilityManager
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class AgentSnapSignals(private val ctx: Context, private val hashKey: ByteArray) {

    @Volatile private var callActive = false
    @Volatile private var callStartedAt = 0L

    private val remoteControlPackages = listOf(
        "com.anydesk.anydeskandroid", "com.teamviewer.quicksupport.market",
        "com.teamviewer.teamviewer.market.mobile", "com.rsupport.mvagent", "com.airdroid.remote",
    )

    fun start() {
        val tm = ctx.getSystemService(TelephonyManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            tm.registerTelephonyCallback(ctx.mainExecutor, object : TelephonyCallback(), TelephonyCallback.CallStateListener {
                override fun onCallStateChanged(state: Int) {
                    val active = state != TelephonyManager.CALL_STATE_IDLE
                    if (active && !callActive) callStartedAt = System.currentTimeMillis()
                    callActive = active
                }
            })
        }
    }

    /** A screen being mirrored or recorded shows up as an extra presentation display. */
    private fun screenShared(): Boolean {
        val dm = ctx.getSystemService(DisplayManager::class.java)
        return dm.getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION).isNotEmpty() ||
            dm.displays.any { it.displayId != Display.DEFAULT_DISPLAY && (it.flags and Display.FLAG_PRIVATE) == 0 }
    }

    private fun remoteAccessApp(): Boolean = remoteControlPackages.any {
        try { ctx.packageManager.getPackageInfo(it, 0); true } catch (e: Exception) { false }
    }

    /** Accessibility services that can read or drive the screen, other than the system's own. */
    private fun accessibilityOverlay(): Boolean {
        val am = ctx.getSystemService(AccessibilityManager::class.java)
        return am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .any { !it.resolveInfo.serviceInfo.packageName.startsWith("com.google.android") }
    }

    fun keyedHash(number: String): String {
        val digits = number.filter { it.isDigit() }.takeLast(10)
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(hashKey, "HmacSHA256")) }
        return mac.doFinal(digits.toByteArray()).joinToString("") { "%02x".format(it) }.take(16)
    }

    /** The `tel` envelope for POST /v1/events. */
    fun envelope(deviceId: String, deviceBoundAt: Long, callerNumber: String?, callerInContacts: Boolean): Map<String, Any?> = mapOf(
        "device_id" to MessageDigest.getInstance("SHA-256").digest(deviceId.toByteArray()).joinToString("") { "%02x".format(it) }.take(32),
        "device_age_h" to (System.currentTimeMillis() - deviceBoundAt) / 3_600_000.0,
        "call_active" to callActive,
        "call_secs" to if (callActive) ((System.currentTimeMillis() - callStartedAt) / 1000).toInt() else 0,
        "caller_h" to callerNumber?.let { keyedHash(it) },
        "caller_in_contacts" to callerInContacts,
        "screen_share" to screenShared(),
        "remote_access_app" to remoteAccessApp(),
        "accessibility_overlay" to accessibilityOverlay(),
    )
}
