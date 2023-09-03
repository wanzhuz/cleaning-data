file = "/Users/wanzhu_zheng/Downloads/MergedAuth.log"
colnames = c("date-time", "logging-host", "app", "PID", "message")

lines = readLines(file, warn = FALSE)
l = lines[!grepl("^#\\s*", lines) & lines != ""]
ll = gsub("^([a-zA-z]+ [ |0-9]+ [0-9:]+) ([^ ]+) ([^\\[|^:]+)([\\[0-9]+\\]:?|:)) \\(", "\\1: (", l)

# match lines
d = grepl("^([a-zA-z]+ [ |0-9]+ [0-9:]+) ([^ ]+) ([^\\[|^:]+)([\\[0-9]+\\]:?|:|[\\[0-9]+\\]:?:) (.*)$", ll, perl = TRUE)
table(d)

# check matches
m = gregexpr("^([a-zA-z]+ [ |0-9]+ [0-9:]+) ([^ ]+) ([^\\[|^:]+)([\\[0-9]+\\]:?|:|[\\[0-9]+\\]:?:) (.*)$", ll, perl = TRUE)
table(sapply(m, length)) # check matches for each line
table(sapply(m, "[", 1) == 1) # check starting position
mlen = sapply(m, function(x) attr(x, "match.length"))
table(mlen)
table(mlen == nchar(ll)) # verify length of match = number of char in each string
m[[1]]

# check for substrings
s = attr(m[[1]], "capture.start")
substring(ll[1], s, s + attr(m[[1]], "capture.length"))

matr = mapply(function(str, match) {
  s = attr(match, "capture.start")
  substring(str, s, s + attr(match, "capture.length"))
}, ll, m)

# transpose into dataframe
df = as.data.frame(t(matr))

# clean up dataframe
names(df) = colnames # rename cols
rownames(df) = NULL # get rid of row names
df$app = gsub("\\[|:", "", df$app) # get rid of unnecessary characters
df$PID = gsub("\\[|\\]|:| ", "", df$PID) # get rid of unnecessary characters
df[df == ""] = NA
df[nchar(as.character(df)) == 0] = NA

# Create a new column `log_file` based on logging-host values
df$`log-file` = with(df, ifelse(`logging-host` == "ip-172-31-27-153 ", "auth.log",
                      ifelse(`logging-host` == "ip-10-77-20-248 ", "auth2.log",
                             ifelse(`logging-host` == "combo ", "Linux_2k.log",
                                    ifelse(`logging-host` == "LabSZ ", "SSH_2k.log", "Mac_2k.log")))))

# check if present PID are numbers
df$PID = as.numeric(df$PID)
is.numeric(df$PID)

# count number of lines in each log file
auth = table(grepl("auth\\.log", df$`log-file`))[["TRUE"]]
auth
auth2 = table(grepl("auth2\\.log", df$`log-file`))[["TRUE"]]
auth2
linux = table(grepl("Linux_2k\\.log", df$`log-file`))[["TRUE"]]
linux
mac = table(grepl("Mac_2k\\.log", df$`log-file`))[["TRUE"]]
mac
ssh = table(grepl("SSH_2k\\.log", df$`log-file`))[["TRUE"]]
ssh

# check if number of lines in subsets dd up to total lines
auth + auth2 + linux + mac + ssh == length(df$`log-file`)

# subset all log files
auth_df = subset(df, df$`log-file` == "auth.log")
auth2_df = subset(df, df$`log-file` == "auth2.log")
linux_df = subset(df, df$`log-file` == "Linux_2k.log")
mac_df = subset(df, df$`log-file` == "Mac_2k.log")
ssh_df = subset(df, df$`log-file` == "SSH_2k.log")

# auth.log
auth_df$`date-time` = as.POSIXct(auth_df$`date-time`, format="%b %d %H:%M:%S") 
range(auth_df$`date-time`) # range of dates
as.numeric(ceiling(as.numeric(difftime(max(auth_df$`date-time`), 
                                                       min(auth_df$`date-time`), units = "days"))))

# auth2.log
auth2_df$`date-time` = as.POSIXct(auth2_df$`date-time`, format="%b %d %H:%M:%S") 
range(auth2_df$`date-time`) # range of dates
as.numeric(ceiling(as.numeric(difftime(max(auth2_df$`date-time`), 
                                                    min(auth2_df$`date-time`), units = "days"))))

# linux
linux_df$`date-time` = as.POSIXct(linux_df$`date-time`, format="%b %d %H:%M:%S") 
range(linux_df$`date-time`) # range of dates
as.numeric(ceiling(as.numeric(difftime(max(linux_df$`date-time`), 
                                                    min(linux_df$`date-time`), units = "days"))))

# mac
mac_df$`date-time` = as.POSIXct(mac_df$`date-time`, format="%b %d %H:%M:%S") 
range(mac_df$`date-time`) # range of dates
as.numeric(ceiling(as.numeric(difftime(max(mac_df$`date-time`), 
                                       min(mac_df$`date-time`), units = "days"))))

# ssh
ssh_df$`date-time` = as.POSIXct(mac_df$`date-time`, format="%b %d %H:%M:%S") 
range(ssh_df$`date-time`) # range of dates
as.numeric(ceiling(as.numeric(difftime(max(ssh_df$`date-time`), 
                                       min(ssh_df$`date-time`), units = "days"))))


# check if app names contain numbers
df[grepl("[0-9]+", df$app), "app"]

# most common app name for each logging host
aggregate(app ~ `logging-host`, data = df, FUN = function(x) {
  names(which.max(table(x)))
})

# find valid log-ins
v = subset(df, grepl("accepted|new session|^connection|^successful", message, ignore.case = TRUE))
v$IP = str_extract_all(v$message, "(\\d{1,3}\\.){3}\\d{1,3}")
v$IP = sapply(v$IP, function(x) ifelse(is.character(x) & length(x) > 1, x[[1]], x))
v$user = str_extract_all(v$message, "(?<=for )[a-zA-Z0-9]+(\\_[a-zA-Z]+)?(\\_[0-9]+)?|(?<=user )[a-zA-Z0-9]+(\\_[a-zA-Z]+)?(\\_[0-9]+)?")
v$user = sapply(v$user, function(x) ifelse(is.character(x) & length(x) > 1, x[[1]], x))
head(v)

# find invalid log-ins
inv = subset(df, grepl("invalid|failure|error|bad", message, ignore.case = TRUE))
inv$IP = str_extract_all(inv$message, "(\\d{1,3}\\.){3}\\d{1,3}")
inv$IP = sapply(inv$IP, function(x) ifelse(is.character(x) & length(x) > 1, x[[2]], x))
inv$user = str_extract_all(inv$message, "(?<= user )[a-zA-Z0-9-.]+|(?<=by )[a-zA-Z0-9-.]+|(?<=for )[a-zA-Z0-9-.]+|(?<= user=)[a-zA-Z0-9-.]+")
inv$user = sapply(inv$user, function(x) ifelse(is.character(x) & length(x) > 1, x[[1]], x))
head(inv)

sort(table(inv$domain), decreasing = TRUE)[1:50] # top 50 domains
users_by_ip = aggregate(user ~ IP, data = inv, FUN = function(x) {paste(unique(x), collapse = ", ")})
head(users_by_ip)
ip_by_users = aggregate(IP ~ user, data = inv, FUN = function(x) {paste(unique(x), collapse = ", ")})
head(ip_by_users)

# compare valid and invalid
common_ip <- intersect(v$IP, inv$IP)
head(common_ip)

# function gets domain from IP addresses
get_domain = function(ip) {
  sub("\\.[^\\.]*$", "", ip)
}

# find common domains
ip_by_users$domain = sapply(strsplit(as.character(ip_by_users$IP), ", "),
                             function(ips) paste0(sapply(ips, get_domain), collapse = ", "))

# compare domains of each user
domains = unlist(strsplit(ip_by_users$domain, ", "))
freq = table(domains)
freq = freq[order(freq, decreasing = TRUE)]
head(freq)

# too many failures
fail = grep("too many authentication failures|error: maximum authentication attempts exceeded", inv$message, ignore.case = TRUE)
ip_fail = sort(inv$IP[fail], na.last = TRUE)
head(ip_fail)

# find all sudo
sudo = subset(df, grepl("sudo", app, ignore.case = TRUE))
sudo$executable = str_extract(sudo$message, "(?<=COMMAND=)/\\S+")
sudo = sudo[!is.na(sudo$executable), ] # cleans up dataframe by grouping open/close into one session
sudo$user = str_extract(sudo$message, "(?<=USER=)\\S+")
sudo = subset(sudo, select = c("logging-host", "app", "executable", "user")) # keep useful columns
names(sudo)[1] = "machine"
head(sudo)
