package main

const index = `
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Token generator">
    <meta name="author" content="">

    <title>Token generator</title>

    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" integrity="sha384-WskhaSGFgHYWDcbwN70/dfYBj47jz9qbsMId/iRN3ewGhXQFZCSftd1LZCfmhktB" crossorigin="anonymous">

    <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.0.13/css/all.css" integrity="sha384-DNOHZ68U8hZfKXOrtjWvjxusGo9WQnrNx2sqG0tfsghAvtVlRW3tvkXWZh58N9jp" crossorigin="anonymous">
  </head>

  <body class="bg-light">

    <div class="container">
      <div class="py-5 text-center">
        <h2>Your token</h2>
        <p class="lead">Below is the token you should paste as a password in your <code>.netrc</code> file.</p>
      </div>

      <div class="row">
        <div class="col-md-2"></div>
        <div class="col-md-8 order-md-1">
          <form class="needs-validation" novalidate>

                <div class="mb-3">
                    <h5>Token</h5>
                  <div class="input-group">
                    <div class="input-group-prepend">
                      <span class="input-group-text"><i class="fas fa-user-secret"></i></span>
                    </div>
                    <input type="text" class="form-control" id="username" value="{{.Token}}" readonly>
                    <!--
                    <div class="input-group-append">
                      <span class="input-group-text"><i class="fas fa-clipboard"></i></span>
                    </div>
                    -->
                  </div>
                </div>

                <div class="mb-3">
                    <h5><code>.netrc</code> content</h5>
                  <div class="input-group">
                    <div class="input-group-prepend">
                      <span class="input-group-text"><i class="fas fa-file"></i></span>
                    </div>
                    <textarea type="text" class="form-control col-xs-12" rows=4 wrap=soft readonly>{{.Netrc}} </textarea>
                    <!--
                    <div class="input-group-append">
                      <span class="input-group-text"><i class="fas fa-clipboard"></i></span>
                    </div>
                    -->
                  </div>
                </div>
          </form>
        </div>
      </div>

      <footer class="my-5 pt-5 text-muted text-center text-small">
        <p class="mb-1">&copy; 2018 Thibault Jamet</p>
      </footer>
    </div>
  </body>
</html>
`
