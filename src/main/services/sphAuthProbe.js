"use strict";

import { net, session } from "electron";
import {
  SPH_AUTH_PROBE,
  isSphSessionInvalid,
  isSphSessionValid,
} from "../../shared/loginState.js";

const DEFAULT_TIMEOUT_MS = 12000;

/**
 * 真实探测视频号会话是否仍然有效。
 *
 * 背景：sessionid 不按时间过期，服务端可以随时作废它；此时 cookie 仍在 jar 里、
 * expires 也没到，只看 cookie 会把失效账号显示成「已登录」，用户发布时才失败。
 * 这里直接调用视频号鉴权接口（auth_data）拿 errCode 作为最终判据。
 *
 * 走传入 partition 对应的 session，因此会自动带上该分区的 cookie，
 * 不需要手工拼 Cookie 头，也不会影响其他分区。
 *
 * 网络异常一律返回 `{ ok: false }`（未知），由调用方回退到 cookie 判定，
 * 避免断网时把正常账号误判成未登录。
 *
 * @param {string} partition 如 `persist:sph视频号`
 * @param {number} [timeoutMs]
 * @returns {Promise<{ok:boolean, loggedIn?:boolean, errCode?:number, reason?:string}>}
 */
export function probeSphSession(partition, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    let request;
    try {
      const ses = session.fromPartition(String(partition || "").split("-")[0]);
      request = net.request({
        method: SPH_AUTH_PROBE.method,
        url: SPH_AUTH_PROBE.url,
        session: ses,
        useSessionCookies: true,
        redirect: "follow",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/plain, */*",
          Origin: "https://channels.weixin.qq.com",
          Referer: SPH_AUTH_PROBE.referer,
        },
      });
    } catch (e) {
      return done({ ok: false, reason: `创建请求失败: ${e.message || e}` });
    }

    const timer = setTimeout(() => {
      try {
        request.abort();
      } catch (_) {
        /* ignore */
      }
      done({ ok: false, reason: "探测超时" });
    }, timeoutMs);

    request.on("response", (response) => {
      let raw = "";
      response.on("data", (chunk) => {
        raw += chunk;
      });
      response.on("end", () => {
        clearTimeout(timer);
        let payload = null;
        try {
          payload = JSON.parse(raw);
        } catch (_) {
          return done({
            ok: false,
            reason: `响应非 JSON (status=${response.statusCode})`,
          });
        }
        if (isSphSessionInvalid(payload)) {
          const code = payload.errCode != null ? payload.errCode : payload.errcode;
          return done({
            ok: true,
            loggedIn: false,
            errCode: Number(code),
            reason: "视频号会话已失效（服务端已作废）",
          });
        }
        if (isSphSessionValid(payload)) {
          return done({ ok: true, loggedIn: true, errCode: 0, reason: "" });
        }
        // 其它错误码含义不明，按「未知」处理，交给 cookie 判定兜底
        const code = payload.errCode != null ? payload.errCode : payload.errcode;
        return done({ ok: false, reason: `未知 errCode=${code}` });
      });
    });

    request.on("error", (e) => {
      clearTimeout(timer);
      done({ ok: false, reason: `请求失败: ${(e && e.message) || e}` });
    });

    request.write(SPH_AUTH_PROBE.body);
    request.end();
  });
}
