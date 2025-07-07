def get_pagination_range(current_page, total_pages, neighbors=2):
    """
    Generates a list of page numbers for pagination, including ellipses.
    e.g., [1, None, 5, 6, 7, None, 10] for current_page=6, total_pages=10
    None represents an ellipsis.
    """
    if total_pages <= (2 * neighbors + 1) + 2: # Show all if not many (e.g., 1 ... 3 4 5 ... 7)
        return list(range(1, total_pages + 1))

    page_range = []
    # Ensure first page is always added
    page_range.append(1)

    # Ellipsis after first page?
    if current_page > neighbors + 2:
        page_range.append(None) # Represents '...'

    # Pages around current_page
    start_range = max(2, current_page - neighbors)
    end_range = min(total_pages - 1, current_page + neighbors)

    for i in range(start_range, end_range + 1):
        if i not in page_range:
            page_range.append(i)

    # Ellipsis before last page?
    if current_page < total_pages - neighbors - 1:
        # Avoid double ellipsis if last page is close or already None
        if not page_range or page_range[-1] is not None:
             if total_pages -1 not in page_range : # ensure no ellipsis if next is last page
                page_range.append(None) # Represents '...'

    # Ensure last page is always added (if not already)
    if total_pages not in page_range:
        page_range.append(total_pages)
        
    # Remove potential leading None if page_range starts with [1, None, 2 ...]
    if len(page_range) > 1 and page_range[0] == 1 and page_range[1] is None and (len(page_range) == 2 or page_range[2] == 2):
        page_range.pop(1)
        
    return page_range