#!/bin/bash
DOMAINS=(
  wordware.ai gumloop.com firecrawl.dev e2b.dev lindy.ai relevanceai.com
  composio.dev vapi.ai humanloop.com letta.com crewai.com browser-use.com
  dust.tt browserbase.com modal.com reworkd.ai recall.ai fixie.ai
  cognition.ai bland.ai windsurf.com induced.ai cassidyai.com mem0.ai
  plandex.ai agno.com superagi.com flowise.ai trigger.dev mirascope.com
  agentscale.ai stakpak.dev smythos.com calltree.ai agentin.ai
  agentuity.com rowboatlabs.com cyberdesk.io sweep.dev continue.dev
  holmesgpt.dev daytona.io anythingllm.com openinterpreter.com
  agentgpt.reworkd.ai fastagency.ai langroid.github.io bondai.dev
  godmode.space spell.so maige.app avanz.ai heymoon.ai
  flowiseai.com vanna.ai questflow.ai rebyte.ai taskade.com
)

OUTPUT="harvested_emails.csv"
echo "company,domain,email,source" > $OUTPUT

for domain in "${DOMAINS[@]}"; do
  echo -n "[$domain] "
  result=$(theHarvester -d "$domain" -b github-code -l 200 2>&1 | grep -E "@$domain" | grep -v "cmartorella" | tr '\n' '|')
  if [ -n "$result" ]; then
    echo "✅ $result"
    for email in $(echo "$result" | tr '|' '\n'); do
      [ -n "$email" ] && echo "$domain,$domain,$email,github-code" >> $OUTPUT
    done
  else
    echo "—"
    echo "$domain,$domain,,not_found" >> $OUTPUT
  fi
  sleep 1.5
done

echo ""
echo "=== RÉSULTAT ==="
grep -v "not_found" $OUTPUT | grep -v "^company" | wc -l
echo "emails trouvés"
