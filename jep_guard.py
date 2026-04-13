import os
import json
import time
import uuid
import hashlib
import secrets
from pathlib import Path
from typing import Dict, Any, List, Optional

# --- 常量定义 ---
HIGH_RISK_COMMANDS = ['rm', 'rmdir', 'mv', 'cp', 'format', 'dd', 'truncate']
HOME_DIR = str(Path.home())
CONFIG_PATH = os.path.join(HOME_DIR, '.jep-guard-config.json')
DEFAULT_LOG_PATH = os.path.join(HOME_DIR, '.jep-guard-audit.log')


# ==========================================
# 1. 配置管理模块 (Config Management)
# ==========================================
class ConfigManager:
    @staticmethod
    def read_config() -> Dict[str, Any]:
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "logLevel": "minimal",
                "jepPrivateKey": None,
                "warnOnInstall": True,
                "logPath": DEFAULT_LOG_PATH
            }

    @staticmethod
    def save_config(config: Dict[str, Any]):
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)


# ==========================================
# 2. 核心拦截与日志模块 (Sidecar & Audit)
# ==========================================
class JEPGuardCore:
    @staticmethod
    def parse_auth_token(env_value: str) -> Optional[Dict]:
        if not env_value:
            return None
        try:
            parsed = json.loads(env_value)
            if isinstance(parsed, dict) and 'id' in parsed and 'expires' in parsed:
                return parsed
        except json.JSONDecodeError:
            pass
        return None

    @staticmethod
    def generate_receipt(action: Dict, user: str, config: Dict) -> Dict:
        """模拟 JEP SDK 生成凭证 (Issue #3 修复：无密钥不签发)"""
        private_key_hex = config.get('jepPrivateKey')
        if not private_key_hex:
            return {"hasReceipt": False}

        try:
            # 校验密钥格式
            bytes.fromhex(private_key_hex)
            if len(private_key_hex) != 64:  # 32 bytes = 64 hex chars
                raise ValueError("Invalid key length")

            # 模拟签名过程
            action_str = json.dumps(action, sort_keys=True).encode('utf-8')
            decision_hash = hashlib.sha256(action_str).hexdigest()

            # 模拟签名的哈希收据
            receipt_hash = hashlib.sha256(f"{decision_hash}{private_key_hex}".encode('utf-8')).hexdigest()

            return {
                "hasReceipt": True,
                "receiptHash": receipt_hash,
                "signed": f"0x{secrets.token_hex(64)}"  # 模拟生成的签名
            }
        except Exception as e:
            return {"hasReceipt": False, "error": str(e)}

    @staticmethod
    def log_action(command: str, args: List[str], auth: Dict, user: str, config: Dict) -> Dict:
        """记录操作并根据隐私级别进行脱敏 (Issue #1 修复)"""
        log_entry = {
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime()),
            "command": command,
            "user": user,
            "sessionId": auth.get('id') if auth else str(uuid.uuid4())
        }

        log_level = config.get('logLevel', 'minimal')

        if log_level == 'verbose':
            log_entry['args'] = args
            log_entry['warning'] = 'VERBOSE MODE: Arguments may contain sensitive data'
        elif log_level == 'normal':
            # 脱敏常见敏感词汇
            sensitive_patterns = ['token', 'key', 'secret', 'pass', 'auth']
            redacted_args = []
            for arg in args:
                if any(p in arg.lower() for p in sensitive_patterns):
                    redacted_args.append('[REDACTED]')
                else:
                    redacted_args.append(arg)
            log_entry['args'] = redacted_args

        # 生成收据
        if config.get('jepPrivateKey'):
            jep = JEPGuardCore.generate_receipt({"command": command, "args": args}, user, config)
            if jep.get("hasReceipt"):
                log_entry['jepReceiptHash'] = jep['receiptHash']

        # 写入日志文件
        log_path = config.get('logPath', DEFAULT_LOG_PATH)
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"Failed to write audit log: {e}")

        return log_entry

    @staticmethod
    def before_command(command: str, args: List[str], context: Any) -> Dict:
        """主拦截器钩子 (Hook: beforeCommand)"""
        config = ConfigManager.read_config()
        auth_token = JEPGuardCore.parse_auth_token(context.env.get('JEP_TEMP_AUTH', ''))

        # 始终记录日志 (包含隐私控制)
        JEPGuardCore.log_action(command, args, auth_token, context.user, config)

        # 非高危命令直接放行
        if command not in HIGH_RISK_COMMANDS:
            return {"allow": True}

        # 检查 Token 是否有效 (5分钟有效期)
        if auth_token and auth_token.get('expires', 0) > int(time.time()):
            return {"allow": True}

        # 请求人工确认
        display_cmd = command if config.get('logLevel') == 'minimal' else f"{command} {' '.join(args)}"
        choice = context.ui.confirm(
            title="⚠️ High-Risk Operation",
            message=f"Execute: {display_cmd}",
            buttons=['✅ Allow Once', '🚫 Deny', '⚙️ Settings']
        )

        if choice == '✅ Allow Once':
            new_token = {
                "id": str(uuid.uuid4()),
                "expires": int(time.time()) + 300,  # 5分钟后过期
                "command": command,
                "createdAt": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
            }
            return {
                "allow": True,
                "env": {"JEP_TEMP_AUTH": json.dumps(new_token)}
            }

        if choice == '⚙️ Settings':
            current_level = config.get('logLevel')
            new_level = 'normal' if current_level == 'minimal' else 'verbose' if current_level == 'normal' else 'minimal'
            config['logLevel'] = new_level
            ConfigManager.save_config(config)
            context.ui.notify(f"Log level set to {new_level}")

        return {"allow": False, "reason": "User denied"}


# ==========================================
# 3. 安装与命令模块 (Commands & Hooks)
# ==========================================
class JEPCommands:
    @staticmethod
    def on_install(context: Any) -> bool:
        """安装钩子 (Hook: onInstall)"""
        warning = context.ui.confirm(
            title="⚠️ JEP Guard Privacy Warning",
            message=("JEP Guard logs commands to ~/.jep-guard-audit.log\n\n"
                     "By default, ONLY command names are logged (safe).\n"
                     "You can change this in settings.\n\n"
                     "Continue installation?"),
            buttons=['✅ Yes, continue', '❌ Cancel']
        )
        if warning != '✅ Yes, continue':
            return False

        config = {
            "logLevel": "minimal",
            "jepPrivateKey": None,
            "warnOnInstall": True,
            "logPath": DEFAULT_LOG_PATH,
            "installedAt": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
        }
        ConfigManager.save_config(config)
        context.ui.notify("✅ JEP Guard Installed. Protection active!")
        return True

    @staticmethod
    def on_uninstall(context: Any) -> bool:
        """卸载钩子 (Hook: onUninstall)"""
        choice = context.ui.confirm(
            title="🗑️ JEP Guard Uninstall",
            message="Delete audit logs?",
            buttons=['✅ Delete logs', '🚫 Keep logs']
        )
        if choice == '✅ Delete logs':
            try:
                os.remove(DEFAULT_LOG_PATH)
            except FileNotFoundError:
                pass
        try:
            os.remove(CONFIG_PATH)
        except FileNotFoundError:
            pass
        context.ui.notify("JEP Guard removed. Thanks for trying!")
        return True

    @staticmethod
    def config_cmd(args: List[str], context: Any) -> Dict:
        """CLI 命令: claw run jep-guard config"""
        config = ConfigManager.read_config()

        if not args:
            display = config.copy()
            if display.get('jepPrivateKey'):
                display['jepPrivateKey'] = '[CONFIGURED]'
            return {"output": json.dumps(display, indent=2), "type": "json"}

        command = args[0]
        if command == 'set' and len(args) >= 3:
            key, value = args[1], " ".join(args[2:])
            if key == 'logLevel':
                if value in ['minimal', 'normal', 'verbose']:
                    config['logLevel'] = value
                    ConfigManager.save_config(config)
                    context.ui.notify(f"Log level set to {value}")
                    return {"output": f"✅ Log level: {value}"}
                return {"output": "❌ Invalid level. Use: minimal, normal, verbose"}

        if command == 'show':
            try:
                with open(config.get('logPath', DEFAULT_LOG_PATH), 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f if line.strip()][-10:]
                    return {"output": "\n".join(lines)}
            except FileNotFoundError:
                return {"output": "No logs found"}

        return {"output": "Commands:\n  config\n  config set logLevel X\n  config show\n  keygen\n  export"}

    @staticmethod
    def keygen_cmd(context: Any) -> Dict:
        """CLI 命令: claw run jep-guard keygen"""
        config = ConfigManager.read_config()

        confirm = context.ui.confirm(
            title="🔑 Generate JEP Key Pair",
            message="This will create a new private key for signing receipts.\n\n⚠️ KEEP THIS KEY SAFE!\nGenerate now?",
            buttons=['✅ Yes', '❌ No']
        )

        if confirm != '✅ Yes':
            return {"output": "Key generation cancelled"}

        # 生成模拟的 Ed25519 密钥对
        private_key = secrets.token_hex(32)
        public_key = hashlib.sha256(private_key.encode('utf-8')).hexdigest()

        config['jepPrivateKey'] = private_key
        ConfigManager.save_config(config)

        context.ui.notify("✅ JEP keys generated and saved")
        return {
            "output": json.dumps({
                "success": True,
                "publicKey": public_key,
                "warning": "Private key saved to config. Never share it!"
            }, indent=2),
            "type": "json"
        }

    @staticmethod
    def export_cmd(context: Any) -> Dict:
        """CLI 命令: claw run jep-guard export"""
        config = ConfigManager.read_config()
        log_path = config.get('logPath', DEFAULT_LOG_PATH)

        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                entries = [json.loads(line) for line in f if line.strip()]

            export_data = {
                "exportedAt": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime()),
                "exportedBy": context.user,
                "logLevel": config.get('logLevel'),
                "warning": '⚠️ VERBOSE LOGS' if config.get('logLevel') == 'verbose' else 'Logs are redacted',
                "entries": entries
            }

            export_path = os.path.join(HOME_DIR, f"jep-export-{int(time.time())}.json")
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)

            return {
                "output": json.dumps(export_data, indent=2),
                "type": "json",
                "message": f"✅ Exported to {export_path}"
            }
        except FileNotFoundError:
            return {"output": json.dumps({"error": "No logs found"}, indent=2), "type": "json"}