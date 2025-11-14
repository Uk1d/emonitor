package httpapi

import "net/http"

type Handlers interface {
    HandleAlerts(http.ResponseWriter, *http.Request)
    HandleAlertDetail(http.ResponseWriter, *http.Request)
    HandleAlertStats(http.ResponseWriter, *http.Request)
    HandleAttackChains(http.ResponseWriter, *http.Request)
    HandleEvents(http.ResponseWriter, *http.Request)
    HandleGraphSubgraph(http.ResponseWriter, *http.Request)
    HandleWebSocket(http.ResponseWriter, *http.Request)
}

func Register(mux *http.ServeMux, h Handlers) {
    mux.HandleFunc("/api/alerts", h.HandleAlerts)
    mux.HandleFunc("/api/alerts/", h.HandleAlertDetail)
    mux.HandleFunc("/api/alerts/stats", h.HandleAlertStats)
    mux.HandleFunc("/api/attack-chains", h.HandleAttackChains)
    mux.HandleFunc("/api/events", h.HandleEvents)
    mux.HandleFunc("/api/graph/subgraph", h.HandleGraphSubgraph)
    mux.HandleFunc("/ws", h.HandleWebSocket)
}