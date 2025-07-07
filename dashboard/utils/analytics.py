def calculate_trend(current, previous):
    """Calculate trend percentage and direction"""
    if previous == 0:
        return {"percentage": 0, "direction": "neutral", "sign": ""}
    
    change = ((current - previous) / previous) * 100
    direction = "up" if change > 0 else "down" if change < 0 else "neutral"
    sign = "+" if change > 0 else ""
    
    return {
        "percentage": abs(round(change, 1)),
        "direction": direction,
        "sign": sign
    }