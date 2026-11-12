(() => {
  const resultElement = document.getElementById("oidc-result");
  if (!resultElement || !window.opener) {
    document.body.textContent = "Sign-in window is no longer connected. Close it and try again.";
    return;
  }

  try {
    const result = JSON.parse(resultElement.textContent || "{}");
    if (result.type === "sentinelai-sso-error") {
      // Hand the server's message to the sign-in page, which shows it.
      window.opener.postMessage(
        { type: "sentinelai-sso-error", message: String(result.message || "") },
        window.location.origin,
      );
      window.close();
      return;
    }
    if (result.type !== "sentinelai-sso-result") {
      throw new Error("Invalid sign-in response");
    }
    window.opener.postMessage(result, window.location.origin);
    window.close();
  } catch {
    document.body.textContent = "Sign-in could not be completed. Close this window and try again.";
  }
})();
