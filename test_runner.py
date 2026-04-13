from jep_guard import JEPGuardCore, JEPCommands


class MockUI:
    def confirm(self, title: str, message: str, buttons: list) -> str:
        print(f"\n[{title}]")
        print(message)
        for i, btn in enumerate(buttons):
            print(f"  {i + 1}. {btn}")
        while True:
            try:
                choice = int(input("\n👉 Select an option (number): ")) - 1
                if 0 <= choice < len(buttons):
                    return buttons[choice]
            except ValueError:
                pass
            print("Invalid choice, try again.")

    def notify(self, message: str, **kwargs):
        if isinstance(message, dict):
            print(f"\n🔔 NOTIFICATION: {message.get('title')} - {message.get('message')}")
        else:
            print(f"\n🔔 NOTIFICATION: {message}")


class MockClawContext:
    def __init__(self):
        self.ui = MockUI()
        self.user = "test_user"
        self.env = {}


def simulate_claw_execution():
    context = MockClawContext()

    print("==================================================")
    print("      🧪 JEP Guard Python Port Simulator        ")
    print("==================================================")

    # 1. 模拟安装
    print("\n--- 1. Simulating Installation ---")
    if not JEPCommands.on_install(context):
        print("Installation cancelled.")
        return

    # 2. 生成密钥 (测试配置模块)
    print("\n--- 2. Generating Keys ---")
    res = JEPCommands.keygen_cmd(context)
    print(res["output"])

    # 3. 模拟执行安全命令 (ls)
    print("\n--- 3. Executing Safe Command: ls -la ---")
    decision = JEPGuardCore.before_command("ls", ["-la"], context)
    if decision.get("allow"):
        print("✅ Command allowed by JEP Guard. Executing `ls -la`...")
    else:
        print("❌ Command blocked.")

    # 4. 模拟执行高危命令 (rm)
    print("\n--- 4. Executing High-Risk Command: rm secret.txt ---")
    decision = JEPGuardCore.before_command("rm", ["secret.txt"], context)

    if decision.get("allow"):
        print("✅ Command allowed! Token injected into env.")
        context.env.update(decision.get("env", {}))

        # 5. 模拟带着 Token 再次执行 (应直接放行)
        print("\n--- 5. Executing rm again within 5 mins (Should auto-allow) ---")
        decision2 = JEPGuardCore.before_command("rm", ["secret.txt"], context)
        if decision2.get("allow"):
            print("✅ Auto-allowed via temporary token!")

    else:
        print(f"❌ Command blocked. Reason: {decision.get('reason')}")

    # 6. 导出审计日志
    print("\n--- 6. Exporting Audit Logs ---")
    res = JEPCommands.export_cmd(context)
    print("Export Result:\n" + res["output"])

    # 7. 模拟卸载
    print("\n--- 7. Simulating Uninstallation ---")
    JEPCommands.on_uninstall(context)


if __name__ == "__main__":
    simulate_claw_execution()