import inquirer from "inquirer";
import figlet from "figlet";
import ora from "ora";
import chalk from "chalk";
import crypto from "node:crypto";
import http from "node:http";
import open from "open";
import cliProgress from "cli-progress";

import { SoundCloudClient } from "./sc.js";
import { parseLine, pickBestMatch } from "./match.js";
import {
	ensureDir,
	exists,
	listJsonFiles,
	readJson,
	writeJson,
	readTextLines,
	appendText,
	resolveRel,
	sleep,
	sha256File
} from "./store.js";
import { makeLogger } from "./logger.js";
import { exchangeTokenAuthCode, refreshToken, makePkce } from "./oauth.js";

/**
 * SC Like — elecktro1337 (t.me/elecktro1337)
 */

const APP_AUTHOR = "elecktro1337 (t.me/elecktro1337)";

const DATA_DIR = resolveRel("data");
const CONFIGS_DIR = resolveRel("data", "configs");
const TOKENS_PATH = resolveRel("data", "tokens.json");
const FOUND_PATH = resolveRel("data", "found_tracks.json");
const NOT_FOUND_PATH = resolveRel("data", "not_found.txt");
const STATE_SEARCH_PATH = resolveRel("data", "state_search.json");
const STATE_LIKES_PATH = resolveRel("data", "state_likes.json");
const ERRORS_LOG_PATH = resolveRel("data", "errors.log");
const STATS_PATH = resolveRel("data", "stats.json");
const TRACKS_TXT = resolveRel("tracks.txt");

const LIKE_DELAY_MS = 2500;
const SEARCH_DELAY_MS = 200;
const SEARCH_LIMIT = 30;

const log = makeLogger({ errorsLogPath: ERRORS_LOG_PATH });

function clearConsole() {
	process.stdout.write("\x1Bc");
}

function header() {
	const art = figlet.textSync("SC Like", { horizontalLayout: "default" });
	console.log(chalk.green(art));
	console.log(chalk.gray("Версия 1.0.4\n"));
	console.log(chalk.gray("Автор: Nikita Shikhovtsev (elecktro1337)\n"));
}

function nowSec() {
	return Math.floor(Date.now() / 1000);
}

function safeId(x) {
	const n = Number(x);
	return Number.isFinite(n) ? n : null;
}

function initStats() {
	const base = readJson(STATS_PATH, null);
	if (base) return base;
	const fresh = {
		updated_at: null,
		search: {
			total_lines: 0,
			parsed_lines: 0,
			found: 0,
			not_found: 0,
			errors: 0,
			started_from: 0,
			finished: false,
			stopped_by_429: false,
			last_index: 0
		},
		likes: {
			total_found: 0,
			processed: 0,
			liked: 0,
			already_liked: 0,
			skipped_by_state: 0,
			errors: 0,
			finished: false,
			stopped_by_429: false,
			last_index: 0
		}
	};
	writeJson(STATS_PATH, fresh);
	return fresh;
}

function saveStats(stats) {
	stats.updated_at = new Date().toISOString();
	writeJson(STATS_PATH, stats);
}

async function selectOrCreateConfig() {
	ensureDir(CONFIGS_DIR);
	const configs = listJsonFiles(CONFIGS_DIR);
	
	const { mode } = await inquirer.prompt([
		{
			type: "list",
			name: "mode",
			message: "Конфиг SoundCloud:",
			choices: [
				{ name: "Загрузить существующий", value: "load" },
				{ name: "Создать новый", value: "create" }
			]
		}
	]);
	
	if (mode === "load") {
		if (!configs.length) {
			log.warn("Нет сохраненных конфигов. Создаем новый.");
			return await createConfig();
		}
		
		const { file } = await inquirer.prompt([
			{
				type: "list",
				name: "file",
				message: "Выбери конфиг:",
				choices: configs.map((c) => ({ name: c, value: c }))
			}
		]);
		
		const cfg = readJson(resolveRel("data", "configs", file), null);
		if (!cfg?.client_id || !cfg?.client_secret || !cfg?.redirect_uri) {
			throw new Error("Конфиг битый/неполный. Удали его и создай заново.");
		}
		log.info(`Конфиг загружен: ${file}`);
		return cfg;
	}
	
	return await createConfig();
}

async function createConfig() {
	const answers = await inquirer.prompt([
		{ type: "input", name: "name", message: "Имя профиля (например: main):", default: "main" },
		{ type: "input", name: "client_id", message: "SoundCloud Client ID:" },
		{ type: "password", name: "client_secret", message: "SoundCloud Client Secret:" },
		{
			type: "input",
			name: "redirect_uri",
			message: "Redirect URI (должен быть добавлен в настройках приложения):",
			default: "http://127.0.0.1:53682/callback"
		}
	]);
	
	const fileName = `${answers.name}.json`;
	const path = resolveRel("data", "configs", fileName);
	
	const cfg = {
		client_id: answers.client_id,
		client_secret: answers.client_secret,
		redirect_uri: answers.redirect_uri
	};
	
	writeJson(path, cfg);
	log.info(`Конфиг сохранен: ${fileName}`);
	return cfg;
}

async function getValidTokens(cfg) {
	const tok = readJson(TOKENS_PATH, null);
	
	if (tok?.access_token && tok?.expires_at && tok.expires_at - nowSec() > 60) return tok;
	
	if (tok?.refresh_token) {
		log.info("Обновляю токен (refresh_token)...");
		const fresh = await refreshToken({
			clientId: cfg.client_id,
			clientSecret: cfg.client_secret,
			refreshToken: tok.refresh_token
		});
		
		const out = { ...fresh, expires_at: nowSec() + (fresh.expires_in || 3600) };
		writeJson(TOKENS_PATH, out);
		return out;
	}
	
	const redirect = new URL(cfg.redirect_uri);
	const listenHost = redirect.hostname;
	const listenPort = Number(redirect.port || 80);
	const callbackPath = redirect.pathname;
	
	const state = crypto.randomBytes(16).toString("hex");
	const pkce = makePkce();
	
	const authorizeUrl = new URL("https://secure.soundcloud.com/authorize");
	authorizeUrl.searchParams.set("client_id", cfg.client_id);
	authorizeUrl.searchParams.set("redirect_uri", cfg.redirect_uri);
	authorizeUrl.searchParams.set("response_type", "code");
	authorizeUrl.searchParams.set("code_challenge", pkce.challenge);
	authorizeUrl.searchParams.set("code_challenge_method", "S256");
	authorizeUrl.searchParams.set("state", state);
	
	log.info("Открываю браузер для авторизации...");
	const code = await new Promise((resolve, reject) => {
		const server = http.createServer((req, res) => {
			try {
				const url = new URL(req.url, cfg.redirect_uri);
				if (url.pathname !== callbackPath) {
					res.writeHead(404);
					res.end("Not Found");
					return;
				}
				
				const gotState = url.searchParams.get("state");
				const gotCode = url.searchParams.get("code");
				const err = url.searchParams.get("error");
				
				if (err) {
					res.writeHead(400);
					res.end(`OAuth error: ${err}`);
					server.close();
					reject(new Error(`OAuth error: ${err}`));
					return;
				}
				if (!gotCode) {
					res.writeHead(400);
					res.end("Missing code");
					server.close();
					reject(new Error("Missing code"));
					return;
				}
				if (gotState !== state) {
					res.writeHead(400);
					res.end("State mismatch");
					server.close();
					reject(new Error("State mismatch"));
					return;
				}
				
				res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
				res.end("<h3>OK. Закрой вкладку и вернись в консоль.</h3>");
				server.close();
				resolve(gotCode);
			} catch (e) {
				server.close();
				reject(e);
			}
		});
		
		server.listen(listenPort, listenHost, async () => {
			await open(authorizeUrl.toString());
		});
	});
	
	log.info("Обмениваю code -> token...");
	const exchanged = await exchangeTokenAuthCode({
		clientId: cfg.client_id,
		clientSecret: cfg.client_secret,
		redirectUri: cfg.redirect_uri,
		code,
		codeVerifier: pkce.verifier
	});
	
	const out = { ...exchanged, expires_at: nowSec() + (exchanged.expires_in || 3600) };
	writeJson(TOKENS_PATH, out);
	return out;
}

function initFiles() {
	ensureDir(DATA_DIR);
	ensureDir(CONFIGS_DIR);
	
	if (!exists(FOUND_PATH)) writeJson(FOUND_PATH, { generated_at: null, tracks_hash: null, found: [] });
	if (!exists(STATE_SEARCH_PATH)) writeJson(STATE_SEARCH_PATH, { tracks_hash: null, next_index: 0, total: 0, updated_at: null });
	if (!exists(STATE_LIKES_PATH)) writeJson(STATE_LIKES_PATH, { liked_ids: {}, updated_at: null });
	if (!exists(NOT_FOUND_PATH)) appendText(NOT_FOUND_PATH, "# not found (Artist - Title) — appended");
	if (!exists(STATS_PATH)) initStats();
}

async function chooseSearchMode(tracksHash) {
	const cached = readJson(FOUND_PATH, null);
	const cacheValid = cached?.tracks_hash === tracksHash && Array.isArray(cached?.found) && cached.found.length > 0;
	
	const searchState = readJson(STATE_SEARCH_PATH, null);
	const canResume =
		searchState?.tracks_hash === tracksHash &&
		Number.isFinite(searchState?.next_index) &&
		searchState.next_index > 0 &&
		searchState.next_index < (searchState.total || Number.MAX_SAFE_INTEGER);
	
	const choices = [];
	if (cacheValid) choices.push({ name: `Использовать кэш найденных для лайкинга (${cached.found.length})`, value: "use_cache" });
	if (canResume) choices.push({ name: `Продолжить обработку с места остановки (строка ${searchState.next_index + 1})`, value: "resume" });
	choices.push({ name: "Обработать файл заново с нуля (сбросить кэш/прогресс поиска)", value: "fresh" });
	
	const { mode } = await inquirer.prompt([
		{ type: "list", name: "mode", message: "Режим обработки tracks.txt:", choices }
	]);
	
	return mode;
}

function loadSearchState() {
	return readJson(STATE_SEARCH_PATH, { tracks_hash: null, next_index: 0, total: 0, updated_at: null });
}

function resetSearchProgress(tracksHash, totalLines) {
	// state_search: начать с нуля
	writeJson(STATE_SEARCH_PATH, {
		tracks_hash: tracksHash,
		next_index: 0,
		total: totalLines,
		updated_at: new Date().toISOString()
	});
	
	// found cache: очистить
	writeJson(FOUND_PATH, {
		generated_at: new Date().toISOString(),
		tracks_hash: tracksHash,
		found: []
	});
	
	// not_found: очищать не обязательно (он накопительный), но можно — если хочешь:
	// fs.writeFileSync(NOT_FOUND_PATH, "# not found ...\n", "utf8");
}

function saveSearchState(st) {
	st.updated_at = new Date().toISOString();
	writeJson(STATE_SEARCH_PATH, st);
}
function loadFoundCache() {
	return readJson(FOUND_PATH, { generated_at: null, tracks_hash: null, found: [] });
}
function saveFoundCache(cache) {
	cache.generated_at = new Date().toISOString();
	writeJson(FOUND_PATH, cache);
}
function loadLikesState() {
	return readJson(STATE_LIKES_PATH, { liked_ids: {}, updated_at: null });
}
function saveLikesState(st) {
	st.updated_at = new Date().toISOString();
	writeJson(STATE_LIKES_PATH, st);
}

// главное: безопасное логирование при активном прогрессбаре
function withBarLog(bar, fn) {
	if (bar) bar.stop();
	fn();
	if (bar) bar.start();
}

async function parseTracks(sc, tracksLines, tracksHash, stats) {
	const spinner = ora({ text: "Подготовка поиска...", spinner: "dots" }).start();
	
	stats.search.total_lines = tracksLines.length;
	stats.search.parsed_lines = tracksLines.length; // по факту — строк в файле (не все могут распарситься)
	stats.search.errors = 0;
	stats.search.stopped_by_429 = false;
	stats.search.finished = false;
	saveStats(stats);
	
	const searchState = loadSearchState();
	let startIndex = 0;
	
	if (searchState.tracks_hash === tracksHash && Number.isFinite(searchState.next_index)) {
		startIndex = searchState.next_index;
	} else {
		searchState.tracks_hash = tracksHash;
		searchState.next_index = 0;
		searchState.total = tracksLines.length;
		saveSearchState(searchState);
	}
	
	const cache = loadFoundCache();
	if (cache.tracks_hash !== tracksHash) {
		cache.tracks_hash = tracksHash;
		cache.found = [];
		saveFoundCache(cache);
	}
	
	spinner.stop();
	log.info(`Поиск: старт с позиции ${startIndex + 1}/${tracksLines.length}`);
	stats.search.started_from = startIndex + 1;
	saveStats(stats);
	
	const bar = new cliProgress.SingleBar(
		{
			format: `${chalk.cyan("{bar}")} {percentage}% | {value}/{total} | {line}`,
			barCompleteChar: "█",
			barIncompleteChar: "░",
			hideCursor: true
		},
		cliProgress.Presets.shades_classic
	);
	
	bar.start(tracksLines.length, startIndex, { line: "" });
	
	for (let i = startIndex; i < tracksLines.length; i++) {
		const line = tracksLines[i];
		bar.update(i + 1, { line: line.length > 42 ? line.slice(0, 39) + "..." : line });
		
		const parsed = parseLine(line);
		if (!parsed) {
			appendText(NOT_FOUND_PATH, line);
			stats.search.not_found += 1;
			stats.search.last_index = i + 1;
			saveStats(stats);
			
			searchState.next_index = i + 1;
			saveSearchState(searchState);
			continue;
		}
		
		const q = `${parsed.artist} ${parsed.title}`;
		
		try {
			const results = await sc.searchTracks({ q, limit: SEARCH_LIMIT });
			
			if (!results.length) {
				appendText(NOT_FOUND_PATH, line);
				stats.search.not_found += 1;
			} else {
				const best = pickBestMatch(parsed, results);
				if (!best) {
					appendText(NOT_FOUND_PATH, line);
					stats.search.not_found += 1;
				} else {
					const id = safeId(best.id);
					if (id) {
						cache.found.push({
							source_line: line,
							query: q,
							track: {
								id,
								title: best.title,
								permalink_url: best.permalink_url,
								user: { username: best.user?.username || "" }
							}
						});
						saveFoundCache(cache);
						stats.search.found += 1;
					} else {
						appendText(NOT_FOUND_PATH, line);
						stats.search.not_found += 1;
					}
				}
			}
			
			searchState.next_index = i + 1;
			searchState.total = tracksLines.length;
			saveSearchState(searchState);
			
			stats.search.last_index = i + 1;
			saveStats(stats);
			
			await sleep(SEARCH_DELAY_MS);
		} catch (e) {
			const status = e?.response?.status;
			const payload = e?.response?.data;
			
			stats.search.errors += 1;
			stats.search.last_index = i + 1;
			saveStats(stats);
			
			// фикс склейки: остановить бар -> лог -> запустить бар обратно
			bar.stop();
			log.error(`Ошибка при поиске на строке ${i + 1}: ${line}`, payload || e?.message);
			
			if (status === 429) {
				log.warn("Получен 429 при поиске. Останавливаю работу с сохранением прогресса.");
				stats.search.stopped_by_429 = true;
				saveStats(stats);
				return { stoppedBy429: true, cache: loadFoundCache() };
			}
			
			bar.start(tracksLines.length, i + 1, { line: "" });
			await sleep(1000);
		}
	}
	
	bar.stop();
	stats.search.finished = true;
	saveStats(stats);
	
	log.info("Поиск завершен.");
	return { stoppedBy429: false, cache: loadFoundCache() };
}

async function likeFlow(sc, foundCache, stats) {
	const likesState = loadLikesState();
	
	stats.likes.total_found = foundCache.found.length;
	stats.likes.processed = 0;
	stats.likes.liked = 0;
	stats.likes.already_liked = 0;
	stats.likes.skipped_by_state = 0;
	stats.likes.errors = 0;
	stats.likes.finished = false;
	stats.likes.stopped_by_429 = false;
	saveStats(stats);
	
	log.info(
		`Лайки: найдено ${stats.likes.total_found}, ` +
		`обработано ${stats.likes.processed}, ` +
		`не найдено ${stats.search.not_found}, ` +
		`ошибок ${stats.likes.errors + stats.search.errors}, ` +
		`уже обработано (state) ${Object.keys(likesState.liked_ids || {}).length}.`
	);
	
	const bar = new cliProgress.SingleBar(
		{
			format: `${chalk.green("{bar}")} {percentage}% | {value}/{total} | {title}`,
			barCompleteChar: "█",
			barIncompleteChar: "░",
			hideCursor: true
		},
		cliProgress.Presets.shades_classic
	);
	
	bar.start(foundCache.found.length, 0, { title: "" });
	
	for (let i = 0; i < foundCache.found.length; i++) {
		const item = foundCache.found[i];
		const id = safeId(item?.track?.id);
		const title = item?.track?.title || item?.source_line || "track";
		
		bar.update(i + 1, { title: title.length > 42 ? title.slice(0, 39) + "..." : title });
		
		if (!id) continue;
		
		// state skip
		if (likesState.liked_ids[String(id)]) {
			stats.likes.skipped_by_state += 1;
			stats.likes.processed += 1;
			stats.likes.last_index = i + 1;
			saveStats(stats);
			continue;
		}
		
		try {
			const liked = await sc.isTrackLikedBestEffort(id);
			if (liked === true) {
				likesState.liked_ids[String(id)] = { at: new Date().toISOString(), status: "already-liked" };
				saveLikesState(likesState);
				
				stats.likes.already_liked += 1;
				stats.likes.processed += 1;
				stats.likes.last_index = i + 1;
				saveStats(stats);
				continue;
			}
			
			await sc.likeTrack(id);
			
			likesState.liked_ids[String(id)] = { at: new Date().toISOString(), status: "liked" };
			saveLikesState(likesState);
			
			stats.likes.liked += 1;
			stats.likes.processed += 1;
			stats.likes.last_index = i + 1;
			saveStats(stats);
			
			await sleep(LIKE_DELAY_MS);
		} catch (e) {
			const status = e?.response?.status;
			const payload = e?.response?.data;
			
			stats.likes.errors += 1;
			stats.likes.last_index = i + 1;
			saveStats(stats);
			
			bar.stop();
			
			if (status === 429) {
				log.error("Получен 429 при лайке. Немедленная остановка. Прогресс сохранен.", payload || e?.message);
				stats.likes.stopped_by_429 = true;
				saveStats(stats);
				return { stoppedBy429: true };
			}
			
			if (status === 409) {
				likesState.liked_ids[String(id)] = { at: new Date().toISOString(), status: "already-liked" };
				saveLikesState(likesState);
				
				stats.likes.already_liked += 1;
				stats.likes.processed += 1;
				saveStats(stats);
				
				bar.start(foundCache.found.length, i + 1, { title: "" });
				continue;
			}
			
			log.error(`Ошибка лайка (id=${id}, title="${title}")`, payload || e?.message);
			
			bar.start(foundCache.found.length, i + 1, { title: "" });
			await sleep(1200);
		}
	}
	
	bar.stop();
	stats.likes.finished = true;
	saveStats(stats);
	
	log.info("Лайкинг завершен.");
	return { stoppedBy429: false };
}

async function main() {
	initFiles();
	const stats = initStats();
	
	clearConsole();
	header();
	
	if (!exists(TRACKS_TXT)) {
		log.error(`Файл tracks.txt не найден: ${TRACKS_TXT}`);
		process.exit(1);
	}
	
	const cfg = await selectOrCreateConfig();
	const tokens = await getValidTokens(cfg);
	
	const sc = new SoundCloudClient({ accessToken: tokens.access_token });
	
	const spinner = ora({ text: "Проверка авторизации...", spinner: "dots" }).start();
	const me = await sc.me();
	spinner.stop();
	
	const username = me?.username || me?.full_name || String(me?.id || "");
	log.info(`Авторизован пользователь SoundCloud: ${username}`);
	
	const tracksHash = sha256File(TRACKS_TXT);
	const lines = readTextLines(TRACKS_TXT);
	
	// сброс счётчиков поиска/лайков (но оставляем накопленный state в файлах)
	stats.search.found = 0;
	stats.search.not_found = 0;
	stats.search.errors = 0;
	
	const mode = await chooseSearchMode(tracksHash);
	
	let foundCache = loadFoundCache();
	
	if (mode === "use_cache") {
		log.info("Использую кэш найденных треков (поиск не выполняется).");
		// stats для поиска не трогаем сильно, но можно обновить found из кэша:
		stats.search.total_lines = lines.length;
		stats.search.parsed_lines = lines.length;
		stats.search.found = foundCache.found.length;
		saveStats(stats);
	} else {
		if (mode === "fresh") {
			log.warn("Сбрасываю прогресс поиска и кэш найденных. Начинаю с нуля.");
			resetSearchProgress(tracksHash, lines.length);
		} else {
			log.info("Продолжаю обработку с места остановки.");
		}
		
		// Обработка (fresh или resume)
		const res = await parseTracks(sc, lines, tracksHash, stats);
		foundCache = res.cache;
		
		if (res.stoppedBy429) {
			log.warn("Работа остановлена из-за 429 на этапе поиска. Запусти позже — продолжит с места.");
			return;
		}
	}
	
	stats.search.found = foundCache.found.length;
	saveStats(stats);
	
	const likeRes = await likeFlow(sc, foundCache, stats);
	
	if (likeRes.stoppedBy429) {
		log.warn("Работа остановлена из-за 429 на этапе лайков. Запусти позже — продолжит с места.");
		return;
	}
	
	log.info("Готово.");
}

main().catch((e) => {
	const payload = e?.response?.data;
	log.error("Фатальная ошибка.", payload || e?.message || e);
	process.exit(1);
});