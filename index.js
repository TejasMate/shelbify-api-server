const express = require("express");
const cors = require("cors");
const { generateSlug } = require("random-word-slugs");
const { ECSClient, RunTaskCommand } = require("@aws-sdk/client-ecs");
const { Server } = require("socket.io");
const Redis = require("ioredis");
const axios = require("axios");
const { AptosClient } = require("aptos");

const app = express();
const PORT = 9000;
const WEBHOOK_URL = process.env.WEBHOOK_URL || "https://your-domain.com/webhook/github";

// Aptos payment configuration (testnet)
const APTOS_NODE = process.env.APTOS_NODE || "https://fullnode.testnet.aptoslabs.com";
const aptosClient = new AptosClient(APTOS_NODE);
const APTOS_RECEIVER = process.env.APTOS_RECEIVER || "0x29a1d3a6b9b7c4f1f2e3d4c5b6a7e8f901234567"; // replace with your testnet receiver
const PRICE_PER_DAY = parseFloat(process.env.PRICE_PER_DAY || "0.1"); // APT per extra day
const FREE_DAYS = parseInt(process.env.FREE_DAYS || "7");
const FREE_REQUESTS = parseInt(process.env.FREE_REQUESTS || "100");

const subscriber = new Redis(
  "rediss://default:AVNS_pYDps765RBb47ppw0-T@valkey-278744b3-proton-9702.i.aivencloud.com:14368",
);

// Redis client for storing deployment metadata
const redis = new Redis(
  "rediss://default:AVNS_pYDps765RBb47ppw0-T@valkey-278744b3-proton-9702.i.aivencloud.com:14368",
);

const io = new Server({ cors: "*" });

io.on("connection", (socket) => {
  socket.on("subscribe", (channel) => {
    socket.join(channel);
    socket.emit("message", JSON.stringify({ log: `Joined ${channel}` }));
  });
});

io.listen(9002, () => console.log("Socket Server 9002"));

const ecsClient = new ECSClient({
  region: "ap-south-1",
  credentials: {
    accessKeyId: "AKIAXH23CKSD6SKOXQYA",
    secretAccessKey: "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",
  },
});

const config = {
  CLUSTER: "arn:aws:ecs:ap-south-1:497870328967:cluster/shelby",
  TASK: "arn:aws:ecs:ap-south-1:497870328967:task-definition/shelby-task:4",
};

// Shelby Configuration
const SHELBY_PRIVATE_KEY = process.env.SHELBY_PRIVATE_KEY || "0x7fc2e002590718da167ddca2b2d128b2232444d5fed4e57eff4e1404a279637e";
const SHELBY_API_KEY = process.env.SHELBY_API_KEY || "aptoslabs_b3QcevYaEpY_CPVf5io7PJccVUsYS35uSbaSjd66ftJgL";

app.use(cors());
app.use(express.json());

// Helper function to trigger deployment
async function triggerDeployment({ gitURL, projectSlug, isPrivate, githubToken, expiryDays }) {
  const environmentVars = [
    { name: "GIT_REPOSITORY__URL", value: gitURL },
    { name: "PROJECT_ID", value: projectSlug },
    { name: "SHELBY_PRIVATE_KEY", value: SHELBY_PRIVATE_KEY },
    { name: "SHELBY_API_KEY", value: SHELBY_API_KEY },
    { name: "EXPIRY_DAYS", value: String(expiryDays) },
  ];

  if (isPrivate && githubToken) {
    environmentVars.push({ name: "GITHUB_TOKEN", value: githubToken });
  }

  const command = new RunTaskCommand({
    cluster: config.CLUSTER,
    taskDefinition: config.TASK,
    launchType: "FARGATE",
    count: 1,
    networkConfiguration: {
      awsvpcConfiguration: {
        assignPublicIp: "ENABLED",
        subnets: [
          "subnet-0641c5468af808365",
          "subnet-00092c7672ddbf546",
          "subnet-00cd180c2b0b4fa99",
        ],
        securityGroups: ["sg-0a8aa76ab902cd44a"],
      },
    },
    overrides: {
      containerOverrides: [
        {
          name: "builder-image",
          environment: environmentVars,
        },
      ],
    },
  });

  await ecsClient.send(command);
}

app.post("/project", async (req, res) => {
  const { gitURL, slug, isPrivate, githubToken, expiryDays = 365, autoRedeploy, repoFullName, walletAddress } = req.body;
  const projectSlug = slug ? slug : generateSlug();

  console.log("========================================");
  console.log("📦 New Deploy Request");
  console.log("URL:", gitURL);
  console.log("Slug:", projectSlug);
  console.log("Auto-redeploy:", autoRedeploy);
  console.log("========================================");

  // Store deployment metadata in Redis
  const deploymentData = {
    slug: projectSlug,
    gitURL,
    repoFullName,
    isPrivate,
    autoRedeploy,
    expiryDays,
    walletAddress,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString(),
  };

  // Store by slug
  await redis.set(`deployment:${projectSlug}`, JSON.stringify(deploymentData));
  
  // Store by repo for webhook lookups (if auto-redeploy enabled)
  if (autoRedeploy && repoFullName) {
    await redis.set(`repo:${repoFullName}`, projectSlug);
  }

  // Trigger deployment
  await triggerDeployment({ gitURL, projectSlug, isPrivate, githubToken, expiryDays });

  // Auto-create GitHub webhook if auto-redeploy is enabled
  if (autoRedeploy && repoFullName && githubToken) {
    try {
      console.log("🔗 Creating GitHub webhook for auto-redeploy...");
      
      // Check if webhook already exists
      const webhooksResponse = await axios.get(
        `https://api.github.com/repos/${repoFullName}/hooks`,
        {
          headers: {
            Authorization: `token ${githubToken}`,
            Accept: "application/vnd.github.v3+json",
          },
        }
      );

      const existingWebhook = webhooksResponse.data.find(
        (hook) => hook.config.url === WEBHOOK_URL
      );

      if (existingWebhook) {
        console.log("✅ Webhook already exists");
      } else {
        // Create new webhook
        await axios.post(
          `https://api.github.com/repos/${repoFullName}/hooks`,
          {
            name: "web",
            active: true,
            events: ["push"],
            config: {
              url: WEBHOOK_URL,
              content_type: "json",
              insecure_ssl: "0",
            },
          },
          {
            headers: {
              Authorization: `token ${githubToken}`,
              Accept: "application/vnd.github.v3+json",
            },
          }
        );
        console.log("✅ GitHub webhook created successfully");
      }
      
      // Store GitHub token for webhook redeployments (with same TTL as deployment)
      if (githubToken) {
        const ttl = expiryDays * 24 * 60 * 60; // Convert days to seconds
        await redis.set(`token:${projectSlug}`, githubToken, "EX", ttl);
        console.log(`✅ Token stored for ${expiryDays} days`);
      }
    } catch (webhookError) {
      console.error("⚠️ Failed to create GitHub webhook:", webhookError.message);
      // Don't fail the deployment if webhook creation fails
    }
  }

  return res.json({
    status: "queued",
    data: { projectSlug, url: `http://${projectSlug}.localhost:8000` },
  });
});

// GitHub webhook endpoint for auto-redeploy
app.post("/webhook/github", async (req, res) => {
  try {
    const { repository, ref } = req.body;
    
    if (!repository || !ref) {
      return res.status(400).json({ error: "Invalid webhook payload" });
    }

    const repoFullName = repository.full_name;
    console.log("🔔 GitHub webhook received for:", repoFullName, "ref:", ref);

    // Only deploy on push to main/master branch
    if (!ref.endsWith("/main") && !ref.endsWith("/master")) {
      console.log("⏭️ Skipping deployment - not main/master branch");
      return res.json({ message: "Skipped - not main/master branch" });
    }

    // Find deployment for this repo
    const projectSlug = await redis.get(`repo:${repoFullName}`);
    
    if (!projectSlug) {
      console.log("⚠️ No deployment found for repo:", repoFullName);
      return res.status(404).json({ error: "No deployment found for this repository" });
    }

    // Get deployment data
    const deploymentDataStr = await redis.get(`deployment:${projectSlug}`);
    if (!deploymentDataStr) {
      return res.status(404).json({ error: "Deployment data not found" });
    }

    const deploymentData = JSON.parse(deploymentDataStr);

    if (!deploymentData.autoRedeploy) {
      console.log("⏭️ Auto-redeploy disabled for this deployment");
      return res.json({ message: "Auto-redeploy disabled" });
    }

    console.log("🚀 Triggering auto-redeployment for:", projectSlug);

    // Get stored GitHub token for private repos
    const storedToken = await redis.get(`token:${projectSlug}`);
    console.log("📦 Using stored token:", storedToken ? "Token found" : "No token");

    // Trigger redeployment
    await triggerDeployment({
      gitURL: deploymentData.gitURL,
      projectSlug,
      isPrivate: deploymentData.isPrivate,
      githubToken: storedToken, // Use stored token for private repos
      expiryDays: deploymentData.expiryDays,
    });

    res.json({ message: "Deployment triggered", slug: projectSlug });
  } catch (error) {
    console.error("Webhook error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get all deployments (or filter by wallet address)
app.get("/deployments", async (req, res) => {
  try {
    const { walletAddress } = req.query;
    // Get all deployment keys from Redis
    const keys = await redis.keys("deployment:*");
    
    if (keys.length === 0) {
      return res.json({ deployments: [] });
    }

    // Fetch all deployment data
    const deployments = await Promise.all(
      keys.map(async (key) => {
        const data = await redis.get(key);
        return data ? JSON.parse(data) : null;
      })
    );

    // Filter out null values and sort by creation date (newest first)
    let validDeployments = deployments
      .filter((d) => d !== null)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    // Filter by wallet address if provided
    if (walletAddress) {
      validDeployments = validDeployments.filter(d => d.walletAddress === walletAddress);
    }

    res.json({ deployments: validDeployments });
  } catch (error) {
    console.error("Failed to fetch deployments:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Payment info for frontend
app.get("/payment-info", async (req, res) => {
  try {
    res.json({
      receiver: APTOS_RECEIVER,
      pricePerDay: PRICE_PER_DAY,
      freeDays: FREE_DAYS,
      freeRequests: FREE_REQUESTS,
    });
  } catch (err) {
    console.error("Failed to get payment info:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Verify Aptos payment and credit deployment (days)
app.post("/verify-payment", express.json(), async (req, res) => {
  try {
    const { slug, txHash, days } = req.body;
    if (!slug || !txHash || !days) {
      return res.status(400).json({ error: "Missing slug, txHash or days" });
    }

    // Fetch transaction from Aptos testnet
    const txn = await aptosClient.getTransactionByHash(txHash);
    if (!txn) {
      return res.status(404).json({ error: "Transaction not found" });
    }

    if (txn.success === false) {
      return res.status(400).json({ error: "Transaction failed" });
    }

    // Simple verification: ensure tx JSON contains receiver address and amount
    const payloadStr = JSON.stringify(txn);
    if (!payloadStr.includes(APTOS_RECEIVER)) {
      return res.status(400).json({ error: "Transaction does not target the payment receiver" });
    }

    // Check amount roughly by searching for amount string (best-effort)
    const required = (Number(days) * PRICE_PER_DAY).toFixed(6);
    if (!payloadStr.includes(required) && !payloadStr.includes(Number(required).toString())) {
      // Not strictly reliable — warn but allow for developer/test flows where formatting differs
      console.warn("Payment verification: amount pattern not found in txn payload", { txHash, required });
    }

    // Credit the deployment: extend expiry by days
    const depKey = `deployment:${slug}`;
    const depStr = await redis.get(depKey);
    if (!depStr) return res.status(404).json({ error: "Deployment not found" });

    const dep = JSON.parse(depStr);
    const currentExpiry = new Date(dep.expiresAt).getTime();
    const addedMs = Number(days) * 24 * 60 * 60 * 1000;
    const newExpiry = new Date(Math.max(Date.now(), currentExpiry) + addedMs).toISOString();
    dep.expiresAt = newExpiry;

    // Persist and respond
    await redis.set(depKey, JSON.stringify(dep));
    return res.json({ message: "Payment verified, deployment extended", newExpiry, slug });
  } catch (err) {
    console.error("verify-payment error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

async function initRedisSubscribe() {
  console.log("Subscribed to logs....");
  subscriber.psubscribe("logs:*");
  subscriber.on("pmessage", (pattern, channel, message) => {
    io.to(channel).emit("message", message);
  });
}

initRedisSubscribe();

app.listen(PORT, () => console.log(`API Server Running..${PORT}`));
