import { readFileSync, writeFileSync, existsSync } from "fs"
import * as yaml from "js-yaml"
import { minimatch } from "minimatch"
import { relative } from "path"

interface IgnoreEntry {
    rule: string
    files: string[]
}

interface Config {
    ignore?: IgnoreEntry[]
}

interface SarifLocation {
    physicalLocation?: {
        artifactLocation?: { uri?: string }
        region?: { startLine?: number }
    }
}

interface SarifResult {
    ruleId?: string
    locations?: SarifLocation[]
}

interface SarifRule {
    id: string
    name: string
}

interface SarifRun {
    results?: SarifResult[]
    tool?: {
        driver?: {
            rules?: SarifRule[]
        }
    }
}

interface Sarif {
    version: string
    runs: SarifRun[]
}

const CONFIG_PATH = ".circomspectignore.yaml"

function normalizeFilePath(uri: string, repoRoot: string): string {
    // Remove file:// prefix
    let filePath = uri.replace(/^file:\/\//, "")
    // Make relative to repo root
    return relative(repoRoot, filePath)
}

function parseFilePattern(pattern: string): { path: string; line?: number } {
    const match = pattern.match(/^(.+):(\d+)$/)
    if (match) {
        return { path: match[1], line: parseInt(match[2], 10) }
    }
    return { path: pattern }
}

function matchesRule(resultRuleId: string, configRule: string, ruleIdToName: Map<string, string>): boolean {
    if (configRule === "*") return true
    if (resultRuleId === configRule) return true
    // Check if config rule matches the rule name
    const ruleName = ruleIdToName.get(resultRuleId)
    if (ruleName && ruleName === configRule) return true
    // Support glob patterns for rule IDs (e.g., "CS00*")
    if (minimatch(resultRuleId, configRule)) return true
    return false
}

function shouldIgnore(
    result: SarifResult,
    config: Config,
    ruleIdToName: Map<string, string>,
    repoRoot: string
): boolean {
    if (!config.ignore || config.ignore.length === 0) return false
    if (!result.ruleId) return false

    const location = result.locations?.[0]?.physicalLocation
    if (!location?.artifactLocation?.uri) return false

    const filePath = normalizeFilePath(location.artifactLocation.uri, repoRoot)
    const resultLine = location.region?.startLine

    for (const entry of config.ignore) {
        if (!matchesRule(result.ruleId, entry.rule, ruleIdToName)) continue

        for (const filePattern of entry.files) {
            const { path: pattern, line: configLine } = parseFilePattern(filePattern)

            // Check if file matches
            if (!minimatch(filePath, pattern)) continue

            // If config specifies a line, check line match
            if (configLine !== undefined) {
                if (resultLine === configLine) return true
            } else {
                // No line specified, match entire file
                return true
            }
        }
    }

    return false
}

function main(): void {
    const args = process.argv.slice(2)

    if (args.length < 2) {
        console.error("Usage: ts-node filter-sarif.ts <input-sarif> <output-sarif>")
        process.exit(1)
    }

    const [inputPath, outputPath] = args
    const repoRoot = process.cwd()

    // Load SARIF
    if (!existsSync(inputPath)) {
        console.error(`Error: Input file not found: ${inputPath}`)
        process.exit(1)
    }

    let sarif: Sarif
    try {
        sarif = JSON.parse(readFileSync(inputPath, "utf-8"))
    } catch (e) {
        console.error(`Error: Failed to parse SARIF file: ${e}`)
        process.exit(1)
    }

    // Load config (or use empty config if missing)
    let config: Config = { ignore: [] }
    if (existsSync(CONFIG_PATH)) {
        try {
            const rawConfig = yaml.load(readFileSync(CONFIG_PATH, "utf-8"))
            config = rawConfig as Config
        } catch (e) {
            console.error(`Error: Failed to parse ${CONFIG_PATH}: ${e}`)
            process.exit(1)
        }
    } else {
        console.log(`Note: No ${CONFIG_PATH} found, skipping filtering`)
    }

    // Build rule ID -> name map from SARIF
    const ruleIdToName = new Map<string, string>()
    const rules = sarif.runs?.[0]?.tool?.driver?.rules ?? []
    for (const rule of rules) {
        ruleIdToName.set(rule.id, rule.name)
    }

    // Filter results
    const originalResults = sarif.runs?.[0]?.results ?? []
    const originalCount = originalResults.length

    const filteredResults = originalResults.filter((result) => !shouldIgnore(result, config, ruleIdToName, repoRoot))

    const filteredCount = originalCount - filteredResults.length

    // Update SARIF
    if (sarif.runs?.[0]) {
        sarif.runs[0].results = filteredResults
    }

    // Write filtered SARIF
    writeFileSync(outputPath, JSON.stringify(sarif, null, 2))

    console.log(
        `Filtered SARIF: ${originalCount} results -> ${filteredResults.length} results (${filteredCount} ignored)`
    )
}

main()
