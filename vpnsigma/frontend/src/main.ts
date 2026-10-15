import { VPNService } from "../bindings/SigmaVPN/internal/service";

const connectButton = document.getElementById("connect-btn") as HTMLButtonElement | null;
const disconnectButton = document.getElementById("disconnect-btn") as HTMLButtonElement | null;
const statusLabel = document.getElementById("status") as HTMLParagraphElement | null;

function setStatus(text: string, className: string) {
    if (!statusLabel) {
        return;
    }
    statusLabel.innerText = text;
    statusLabel.className = className;
}

connectButton?.addEventListener("click", async () => {
    setStatus("Connecting...", "");
    try {
        const result = await VPNService.Connect("1.2.3.4:51820");
        setStatus(result, "status-connected");
    } catch (err) {
        setStatus("Failed: " + (err as Error).message, "status-failed");
    }
});

disconnectButton?.addEventListener("click", async () => {
    try {
        const result = await VPNService.Disconnect();
        setStatus(result, "status-disconnected");
    } catch (err) {
        setStatus("Failed: " + (err as Error).message, "status-failed");
    }
});
