import * as vscode from 'vscode';
import * as CryptoJS from 'crypto-js';
import iconv from 'iconv-lite';

function getSelectedText(): string | undefined {
	const editor = vscode.window.activeTextEditor;
	if (!editor) return;
	const selection = editor.selection;
	return editor.document.getText(selection);
}

function replaceSelectedText(newText: string) {
	const editor = vscode.window.activeTextEditor;
	if (!editor) return;
	const selection = editor.selection;
	editor.edit(editBuilder => {
		editBuilder.replace(selection, newText);
	});
}

function copyToClipboard(text: string) {
	vscode.env.clipboard.writeText(text);
	vscode.window.showInformationMessage(text);
}

function registerTransformCommand(
	command: string,
	transform: (input: string) => string,
	copyOnly = false
) {
	return vscode.commands.registerCommand(command, () => {
		const input = getSelectedText();
		if (!input) {
			vscode.window.showWarningMessage('未选择任何文本。');
			return;
		}
		try {
			const result = transform(input);
			if (copyOnly) {
				copyToClipboard(result);
			} else {
				replaceSelectedText(result);
			}
		} catch (e: any) {
			vscode.window.showErrorMessage(`操作失败: ${e.message}`);
		}
	});
}

// 日志加密参数（固定密钥和 IV）
const fixedKey = CryptoJS.enc.Utf8.parse('01234567890123456789012345678901');
const fixedIv = CryptoJS.enc.Utf8.parse('0123456789012345');

/**
 * 将明文加密为 Hex 编码的 AES-CBC 密文
 * @param text 明文字符串
 * @returns Hex 编码的加密字符串
 */
function encryptLog(text: string): string {
	const encrypted = CryptoJS.AES.encrypt(text, fixedKey, {
		iv: fixedIv,
		mode: CryptoJS.mode.CBC,
		padding: CryptoJS.pad.Pkcs7
	});

	// 将 Base64 密文转为 WordArray，再转 Hex 字符串
	const base64CipherText = encrypted.toString();
	const cipherWordArray = CryptoJS.enc.Base64.parse(base64CipherText);
	return CryptoJS.enc.Hex.stringify(cipherWordArray);
}

/**
 * 解密 Hex 编码的 AES-CBC 密文，返回原始字符串
 * @param hexCipherText Hex 编码的密文
 * @returns 原始字符串
 */
function decryptLog(hexCipherText: string): string {
	try {
		const cipherWordArray = CryptoJS.enc.Hex.parse(hexCipherText);
		const base64CipherText = CryptoJS.enc.Base64.stringify(cipherWordArray);

		const decrypted = CryptoJS.AES.decrypt(base64CipherText, fixedKey, {
			iv: fixedIv,
			mode: CryptoJS.mode.CBC,
			padding: CryptoJS.pad.Pkcs7
		});

		// 把 WordArray 转成 Uint8Array
		const decryptedWords = decrypted.words;
		const decryptedSigBytes = decrypted.sigBytes;

		const byteArray = new Uint8Array(decryptedSigBytes);
		for (let i = 0; i < decryptedSigBytes; i++) {
			byteArray[i] = (decryptedWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
		}

		// 用 iconv-lite 解码为 GBK 字符串
		const gbkDecoded = iconv.decode(Buffer.from(byteArray), 'gbk');

		if (!gbkDecoded) {
			throw new Error('解密失败，可能密文无效或格式错误。');
		}
		return gbkDecoded;
	} catch (e: any) {
		throw new Error(`解密失败: ${e.message}`);
	}
}

export function activate(context: vscode.ExtensionContext) {
	const commands = [
		['encrypt-toolbox.base64Encode', (s: string) => Buffer.from(s).toString('base64')],
		['encrypt-toolbox.base64EncodeCopy', (s: string) => Buffer.from(s).toString('base64'), true],
		['encrypt-toolbox.base64Decode', (s: string) => Buffer.from(s, 'base64').toString()],
		['encrypt-toolbox.base64DecodeCopy', (s: string) => Buffer.from(s, 'base64').toString(), true],
		['encrypt-toolbox.hexEncode', (s: string) => Buffer.from(s).toString('hex')],
		['encrypt-toolbox.hexEncodeCopy', (s: string) => Buffer.from(s).toString('hex'), true],
		['encrypt-toolbox.hexDecode', (s: string) => Buffer.from(s, 'hex').toString()],
		['encrypt-toolbox.hexDecodeCopy', (s: string) => Buffer.from(s, 'hex').toString(), true],
		['encrypt-toolbox.hashMd5', (s: string) => CryptoJS.MD5(s).toString()],
		['encrypt-toolbox.hashMd5Copy', (s: string) => CryptoJS.MD5(s).toString(), true],
		['encrypt-toolbox.hashSha1', (s: string) => CryptoJS.SHA1(s).toString()],
		['encrypt-toolbox.hashSha1Copy', (s: string) => CryptoJS.SHA1(s).toString(), true],
		['encrypt-toolbox.hashSha256', (s: string) => CryptoJS.SHA256(s).toString()],
		['encrypt-toolbox.hashSha256Copy', (s: string) => CryptoJS.SHA256(s).toString(), true],
		['encrypt-toolbox.hashSha512', (s: string) => CryptoJS.SHA512(s).toString()],
		['encrypt-toolbox.hashSha512Copy', (s: string) => CryptoJS.SHA512(s).toString(), true],
		['encrypt-toolbox.toUpperCase', (s: string) => s.toUpperCase()],
		['encrypt-toolbox.toLowerCase', (s: string) => s.toLowerCase()],
		['encrypt-toolbox.toggleCase', (s: string) =>
			Array.from(s).map(ch =>
				ch === ch.toUpperCase() ? ch.toLowerCase() : ch.toUpperCase()
			).join('')
		],
		['encrypt-toolbox.aesLogEncrypt', encryptLog],
		['encrypt-toolbox.aesLogDecrypt', decryptLog]
	];

	commands.forEach(([command, transform, copyOnly = false]) => {
		const disposable = registerTransformCommand(command as string, transform as any, copyOnly as boolean);
		context.subscriptions.push(disposable);
	});
}

export function deactivate() { }
