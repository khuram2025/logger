# Dashboard JavaScript Files

## tag-search.js

Contains the complete tag-based search functionality for the logs page.

### Features:
- Auto-suggest dropdown for search options
- Tag-based filtering system
- Multiple concurrent filters
- URL parameter synchronization
- Tag removal functionality

### Search Options:
- **Source IP** (`srcip`) - Filter by source IP address
- **Destination IP** (`dstip`) - Filter by destination IP address  
- **Destination Port** (`dstport`) - Filter by destination port
- **Protocol** (`protocol`) - Filter by protocol (TCP/UDP/ICMP)

### Usage:
1. User types in search box → Auto-suggest dropdown appears
2. User selects filter type → "Filter Name:" appears in input
3. User adds value → "Filter Name:value"
4. User presses Enter → Tag is created and filter applied
5. User can click × on any tag to remove that filter

### Dependencies:
- Requires DOM elements: `#sourceIpSearch`, `#searchSuggestions`, `#searchTags`
- Requires CSS from `tag-search.css`
- Uses global function: `removeSearchTag(field)`

### Integration:
Include in HTML template:
```html
<script src="{% static 'dashboard/js/tag-search.js' %}"></script>
```