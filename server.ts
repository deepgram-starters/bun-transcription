/**
 * Bun Transcription Starter - Backend Server
 *
 * This is a minimal server providing prerecorded audio transcription
 * powered by Deepgram's speech-to-text service.
 *
 * Key Features:
 * - Contract-compliant API endpoint: POST /api/transcription
 * - Accepts audio file upload (multipart form data)
 * - Supports multiple transcription options via query parameters
 * - JWT session auth with rate limiting (production only)
 * - CORS enabled for frontend communication
 */

// ============================================================================
// IMPORTS
// ============================================================================

import { DeepgramClient } from "@deepgram/sdk";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import TOML from "@iarna/toml";

// ============================================================================
// ENV LOADING - Bun loads .env files automatically
// ============================================================================

// No dotenv needed — Bun natively loads .env files on startup.
// Access variables via process.env or Bun.env.

// ============================================================================
// CONFIGURATION - Customize these values for your needs
// ============================================================================

/**
 * Default transcription model to use when none is specified
 * Options: "nova-3", "nova-2", "nova", "enhanced", "base"
 * See: https://developers.deepgram.com/docs/models-languages-overview
 */
const DEFAULT_MODEL = "nova-3";

/**
 * Server configuration - These can be overridden via environment variables
 */
interface ServerConfig {
  port: number;
  host: string;
}

const config: ServerConfig = {
  port: parseInt(process.env.PORT || "8081"),
  host: process.env.HOST || "0.0.0.0",
};

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

/**
 * Session secret for signing JWTs.
 * Auto-generated in development; set SESSION_SECRET env var in production.
 */
const SESSION_SECRET: string =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

/** JWT expiry time (1 hour) */
const JWT_EXPIRY = "1h";

/**
 * Creates a signed JWT session token
 * @returns Signed JWT string
 */
function createSessionToken(): string {
  return jwt.sign(
    { iat: Math.floor(Date.now() / 1000) },
    SESSION_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
}

/**
 * Validates JWT from Authorization header.
 * Returns an error Response if token is missing or invalid, or null if valid.
 * @param req - Incoming HTTP request
 * @returns Error Response or null if auth is valid
 */
function checkAuth(req: Request): Response | null {
  const authHeader = req.headers.get("Authorization") || "";

  if (!authHeader.startsWith("Bearer ")) {
    return Response.json(
      {
        error: {
          type: "AuthenticationError",
          code: "MISSING_TOKEN",
          message: "Authorization header with Bearer token is required",
        },
      },
      { status: 401, headers: getCorsHeaders() }
    );
  }

  try {
    const token = authHeader.slice(7);
    jwt.verify(token, SESSION_SECRET);
    return null;
  } catch (err: unknown) {
    const jwtErr = err as { name?: string };
    return Response.json(
      {
        error: {
          type: "AuthenticationError",
          code: "INVALID_TOKEN",
          message:
            jwtErr.name === "TokenExpiredError"
              ? "Session expired, please refresh the page"
              : "Invalid session token",
        },
      },
      { status: 401, headers: getCorsHeaders() }
    );
  }
}

// ============================================================================
// API KEY LOADING - Load Deepgram API key from .env
// ============================================================================

/**
 * Loads the Deepgram API key from environment variables.
 * Exits with a helpful error message if the key is not found.
 * @returns The Deepgram API key string
 */
function loadApiKey(): string {
  const apiKey = process.env.DEEPGRAM_API_KEY;

  if (!apiKey) {
    console.error("\n❌ ERROR: Deepgram API key not found!\n");
    console.error("Please set your API key using one of these methods:\n");
    console.error("1. Create a .env file (recommended):");
    console.error("   DEEPGRAM_API_KEY=your_api_key_here\n");
    console.error("2. Environment variable:");
    console.error("   export DEEPGRAM_API_KEY=your_api_key_here\n");
    console.error("Get your API key at: https://console.deepgram.com\n");
    process.exit(1);
  }

  return apiKey;
}

const apiKey = loadApiKey();

// ============================================================================
// SETUP - Initialize Deepgram client
// ============================================================================

const deepgram = new DeepgramClient({ apiKey });

// ============================================================================
// HELPER FUNCTIONS - Modular logic for easier understanding and testing
// ============================================================================

/**
 * Returns standard CORS headers for cross-origin requests.
 * Bun has no CORS middleware, so we add these to every response.
 * @returns Headers object with CORS headers
 */
function getCorsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

/** Shape of the transcription request passed to the Deepgram SDK */
interface TranscriptionRequest {
  url?: string;
  buffer?: Buffer;
  mimetype?: string;
}

/**
 * Validates that either a file or URL was provided in the request
 * @param file - File from form data
 * @param url - URL string from form data
 * @returns Request object for Deepgram, or null if invalid
 */
function validateTranscriptionInput(
  file: File | null,
  url: string | null
): TranscriptionRequest | null {
  // URL-based transcription
  if (url) {
    return { url };
  }

  // File-based transcription — buffer will be populated in handler
  if (file) {
    return { mimetype: file.type };
  }

  // Neither provided
  return null;
}

/**
 * Sends a transcription request to Deepgram
 * @param dgRequest - Request object with url OR buffer+mimetype
 * @param options - Deepgram transcription options (model, language, etc.)
 * @returns Deepgram API response
 */
async function transcribeAudio(
  dgRequest: TranscriptionRequest,
  options: Record<string, unknown>
): Promise<unknown> {
  // URL transcription
  if (dgRequest.url) {
    return await deepgram.listen.v1.media.transcribeUrl({ url: dgRequest.url, ...options });
  }

  // File transcription
  if (dgRequest.buffer) {
    return await deepgram.listen.v1.media.transcribeFile(
      { data: dgRequest.buffer, contentType: dgRequest.mimetype },
      options
    );
  }

  throw new Error("Invalid transcription request");
}

/** Shape of a formatted transcription response */
interface TranscriptionResponse {
  transcript: string;
  words: unknown[];
  metadata: {
    model_uuid?: string;
    request_id?: string;
    model_name: string;
  };
  duration?: number;
}

/**
 * Formats Deepgram's response into a simplified, consistent structure.
 * This is where you'd customize the response format for your application.
 * @param transcriptionResponse - Raw Deepgram API response
 * @param modelName - Name of model used for transcription
 * @returns Formatted response object
 */
function formatTranscriptionResponse(
  transcriptionResponse: any,
  modelName: string
): TranscriptionResponse {
  const transcription = transcriptionResponse;

  const result = transcription?.results?.channels?.[0]?.alternatives?.[0];

  if (!result) {
    throw new Error("No transcription results returned from Deepgram");
  }

  // Build response object
  const response: TranscriptionResponse = {
    transcript: result.transcript || "",
    words: result.words || [],
    metadata: {
      model_uuid: transcription.metadata?.model_uuid,
      request_id: transcription.metadata?.request_id,
      model_name: modelName,
    },
  };

  // Add optional fields if available
  if (transcription.metadata?.duration) {
    response.duration = transcription.metadata.duration;
  }

  return response;
}

/**
 * Formats error responses in a consistent structure
 * @param error - The error that occurred
 * @param statusCode - HTTP status code to return
 * @param code - Machine-readable error code
 * @returns Response object with error JSON and CORS headers
 */
function formatErrorResponse(
  error: Error,
  statusCode: number = 500,
  code?: string
): Response {
  return Response.json(
    {
      error: {
        type: statusCode === 400 ? "ValidationError" : "TranscriptionError",
        code:
          code ||
          (statusCode === 400 ? "MISSING_INPUT" : "TRANSCRIPTION_FAILED"),
        message: error.message || "An error occurred during transcription",
        details: {
          originalError: error.toString(),
        },
      },
    },
    { status: statusCode, headers: getCorsHeaders() }
  );
}

// ============================================================================
// SESSION ROUTES - Auth endpoints (unprotected)
// ============================================================================

/**
 * GET /api/session
 * Issues a signed JWT session token.
 * @returns JSON response with { token }
 */
function handleGetSession(): Response {
  const token = createSessionToken();
  return Response.json({ token }, { headers: getCorsHeaders() });
}

// ============================================================================
// API ROUTES - Define your API endpoints here
// ============================================================================

/**
 * POST /api/transcription
 *
 * Main transcription endpoint. Accepts:
 * - A file upload (multipart/form-data with 'file' field)
 * - A URL to audio file (form data with 'url' field)
 *
 * Query parameters:
 * - model: Deepgram model to use (default: "nova-3")
 * - language: Language code (default: "en")
 * - smart_format: Enable smart formatting (default: "true")
 * - diarize: Enable speaker diarization
 * - punctuate: Enable punctuation
 * - paragraphs: Enable paragraph detection
 * - utterances: Enable utterance detection
 * - filler_words: Enable filler word detection
 *
 * Protected by JWT session auth.
 */
async function handleTranscription(req: Request): Promise<Response> {
  try {
    // Parse query parameters for transcription options
    const url = new URL(req.url);
    const model = url.searchParams.get("model") || DEFAULT_MODEL;
    const language = url.searchParams.get("language") || "en";
    const smartFormat = url.searchParams.get("smart_format") || "true";

    // Build transcription options from query params
    const options: Record<string, unknown> = {
      model,
      language,
      smart_format: smartFormat === "true",
    };

    // Add optional boolean parameters if provided
    const optionalParams = [
      "diarize",
      "punctuate",
      "paragraphs",
      "utterances",
      "filler_words",
    ];
    for (const param of optionalParams) {
      const value = url.searchParams.get(param);
      if (value !== null) {
        options[param] = value === "true";
      }
    }

    // Parse multipart form data
    const formData = await req.formData();
    const file = formData.get("file") as File | null;
    const audioUrl = formData.get("url") as string | null;

    // Validate input — must have either file or URL
    const dgRequest = validateTranscriptionInput(file, audioUrl);
    if (!dgRequest) {
      return formatErrorResponse(
        new Error("Either file or url must be provided"),
        400,
        "MISSING_INPUT"
      );
    }

    // If file provided, read it into a Buffer for the SDK
    if (file) {
      const arrayBuffer = await file.arrayBuffer();
      dgRequest.buffer = Buffer.from(arrayBuffer);
    }

    // Send transcription request to Deepgram
    const transcriptionResponse = await transcribeAudio(dgRequest, options);

    // Format and return response
    const response = formatTranscriptionResponse(transcriptionResponse, model);
    return Response.json(response, { headers: getCorsHeaders() });
  } catch (err) {
    console.error("Transcription error:", err);
    return formatErrorResponse(err as Error);
  }
}

/**
 * GET /api/metadata
 * Returns metadata about this starter application from deepgram.toml.
 * Required for standardization compliance.
 * @returns JSON response with the [meta] section from deepgram.toml
 */
async function handleMetadata(): Promise<Response> {
  try {
    const tomlContent = await Bun.file("deepgram.toml").text();
    const parsed = TOML.parse(tomlContent) as Record<string, unknown>;

    if (!parsed.meta) {
      return Response.json(
        {
          error: "INTERNAL_SERVER_ERROR",
          message: "Missing [meta] section in deepgram.toml",
        },
        { status: 500, headers: getCorsHeaders() }
      );
    }

    return Response.json(parsed.meta, { headers: getCorsHeaders() });
  } catch (error) {
    console.error("Error reading metadata:", error);
    return Response.json(
      {
        error: "INTERNAL_SERVER_ERROR",
        message: "Failed to read metadata from deepgram.toml",
      },
      { status: 500, headers: getCorsHeaders() }
    );
  }
}

/**
 * GET /health
 * Simple health check endpoint.
 * @returns JSON response with { status: "ok" }
 */
function handleHealth(): Response {
  return Response.json({ status: "ok" }, { headers: getCorsHeaders() });
}

// ============================================================================
// SERVER START
// ============================================================================

console.log("\n" + "=".repeat(70));
console.log(`🚀 Backend API Server running at http://localhost:${config.port}`);
console.log("");
console.log(`📡 GET  /api/session`);
console.log(`📡 POST /api/transcription (auth required)`);
console.log(`📡 GET  /api/metadata`);
console.log(`📡 GET  /health`);
console.log("=".repeat(70) + "\n");

Bun.serve({
  port: config.port,
  hostname: config.host,

  /**
   * Main request handler — routes all incoming requests.
   * Bun.serve uses a single fetch() handler instead of middleware chains.
   */
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    // Handle CORS preflight requests
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: getCorsHeaders() });
    }

    // --- Session routes (unprotected) ---

    if (req.method === "GET" && url.pathname === "/api/session") {
      return handleGetSession();
    }

    if (req.method === "GET" && url.pathname === "/api/metadata") {
      return await handleMetadata();
    }

    if (req.method === "GET" && url.pathname === "/health") {
      return handleHealth();
    }

    // --- API routes (auth required) ---

    if (req.method === "POST" && url.pathname === "/api/transcription") {
      const authError = checkAuth(req);
      if (authError) return authError;
      return await handleTranscription(req);
    }

    // --- 404 for all other routes ---

    return Response.json(
      { error: "Not Found", message: "Endpoint not found" },
      { status: 404, headers: getCorsHeaders() }
    );
  },
});
