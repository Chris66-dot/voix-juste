// _worker.js — sert le site (dossier public/) ET la route API /api/chat,
// en un seul fichier compatible avec le glisser-déposer du dashboard Cloudflare.
//
// Comment configurer la clé API :
//   Cloudflare Dashboard → Workers & Pages → (votre projet) → Settings
//   → Variables and Secrets → Add variable
//   Nom : ANTHROPIC_API_KEY   Valeur : sk-ant-xxxxx   (cocher "Encrypt")

const ALLOWED_ORIGINS = "*"; // restreignez à votre domaine si besoin
const MODEL = "claude-haiku-4-5-20251001";
const MAX_TOKENS = 1000;

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

async function handleChat(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Corps de requête JSON invalide." }, 400);
  }

  const { system, messages } = body;
  if (!Array.isArray(messages) || messages.length === 0) {
    return jsonResponse({ error: "Le champ 'messages' est requis." }, 400);
  }
  if (messages.length > 60) {
    return jsonResponse({ error: "Conversation trop longue, démarre une nouvelle session." }, 400);
  }

  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return jsonResponse(
      { error: "Clé API non configurée côté serveur (ANTHROPIC_API_KEY manquante)." },
      500
    );
  }

  try {
    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: MAX_TOKENS,
        system: system || "",
        messages,
      }),
    });

    const data = await upstream.json();

    if (!upstream.ok) {
      return jsonResponse(
        { error: data?.error?.message || "Erreur de l'API Anthropic." },
        upstream.status
      );
    }

    return jsonResponse(data, 200);
  } catch (err) {
    return jsonResponse({ error: "Impossible de contacter l'API Anthropic." }, 502);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/chat") {
      if (request.method === "OPTIONS") {
        return new Response(null, { headers: corsHeaders() });
      }
      if (request.method === "POST") {
        return handleChat(request, env);
      }
      return jsonResponse({ error: "Méthode non autorisée." }, 405);
    }

    // Toute autre requête : servir les fichiers statiques du dossier public/
    return env.ASSETS.fetch(request);
  },
};
